#pragma once
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include "xz.h"

// Android release ART keeps local symbols in an XZ-compressed mini ELF.
// Parse only bounded file buffers; never inspect unrelated process mappings.
class ArtSymbols {
    using Ehdr = ElfW(Ehdr);
    using Shdr = ElfW(Shdr);
    using Sym = ElfW(Sym);
    std::vector<uint8_t> image_, debug_;
    uintptr_t base_ = 0;
    bool ready_ = false;
    static bool range(size_t offset, size_t length, size_t size) {
        return offset <= size && length <= size-offset;
    }
    static const Ehdr *header(const std::vector<uint8_t> &data) {
        if (data.size() < sizeof(Ehdr)) return nullptr;
        auto h = reinterpret_cast<const Ehdr *>(data.data());
        if (memcmp(h->e_ident,ELFMAG,SELFMAG) || h->e_shentsize != sizeof(Shdr) ||
            !range(h->e_shoff,static_cast<size_t>(h->e_shnum)*sizeof(Shdr),data.size())) return nullptr;
        return h;
    }
    static std::vector<Shdr> sections(const std::vector<uint8_t> &data,const Ehdr *h) {
        std::vector<Shdr> out(h->e_shnum);
        memcpy(out.data(),data.data()+h->e_shoff,out.size()*sizeof(Shdr));
        return out;
    }
    static uintptr_t lookup(const std::vector<uint8_t> &data,std::string_view name,bool prefix) {
        auto h=header(data);
        if (!h) return 0;
        auto sh=sections(data,h);
        for (size_t i=0;i<h->e_shnum;++i) {
            if ((sh[i].sh_type!=SHT_SYMTAB && sh[i].sh_type!=SHT_DYNSYM) ||
                sh[i].sh_entsize!=sizeof(Sym) || sh[i].sh_link>=h->e_shnum ||
                !range(sh[i].sh_offset,sh[i].sh_size,data.size())) continue;
            auto strings=sh[sh[i].sh_link];
            if (!range(strings.sh_offset,strings.sh_size,data.size())) continue;
            for (size_t j=0;j<sh[i].sh_size/sizeof(Sym);++j) {
                Sym sym;
                memcpy(&sym,data.data()+sh[i].sh_offset+j*sizeof(Sym),sizeof(sym));
                if (sym.st_shndx==SHN_UNDEF || !sym.st_value || sym.st_name>=strings.sh_size) continue;
                auto s=reinterpret_cast<const char *>(data.data()+strings.sh_offset+sym.st_name);
                auto end=static_cast<const char *>(memchr(s,0,strings.sh_size-sym.st_name));
                if (!end) continue;
                std::string_view candidate(s,end-s);
                if (prefix ? candidate.starts_with(name) : candidate==name) return sym.st_value;
            }
        }
        return 0;
    }
    void decompress() {
        auto h=header(image_);
        if (!h || h->e_shstrndx>=h->e_shnum) return;
        auto sh=sections(image_,h);
        auto strings=sh[h->e_shstrndx];
        if (!range(strings.sh_offset,strings.sh_size,image_.size())) return;
        for (size_t i=0;i<h->e_shnum;++i) {
            constexpr char section[]=".gnu_debugdata";
            if (sh[i].sh_name>=strings.sh_size || strings.sh_size-sh[i].sh_name<sizeof(section) ||
                memcmp(image_.data()+strings.sh_offset+sh[i].sh_name,section,sizeof(section)) ||
                !range(sh[i].sh_offset,sh[i].sh_size,image_.size())) continue;
            auto decoder=xz_dec_init(XZ_DYNALLOC,32*1024*1024);
            if (!decoder) return;
            xz_crc32_init();
            xz_crc64_init();
            xz_buf buffer{};
            buffer.in=image_.data()+sh[i].sh_offset;
            buffer.in_size=sh[i].sh_size;
            xz_ret result=XZ_OK;
            while (result==XZ_OK && debug_.size()<32*1024*1024) {
                auto old=debug_.size();
                debug_.resize(old+65536);
                buffer.out=debug_.data()+old;
                buffer.out_pos=0;
                buffer.out_size=65536;
                result=xz_dec_run(decoder,&buffer);
                debug_.resize(old+buffer.out_pos);
            }
            xz_dec_end(decoder);
            if (result!=XZ_STREAM_END) debug_.clear();
            return;
        }
    }
public:
    bool init() {
        if (ready_) return true;
        struct Image { std::string path; uintptr_t base=0; } image;
        dl_iterate_phdr([](dl_phdr_info *info,size_t,void *data) {
            auto name=info->dlpi_name;
            auto last=name ? strrchr(name,'/') : nullptr;
            if (!last || strcmp(last+1,"libart.so")) return 0;
            auto image=static_cast<Image *>(data);
            image->path=name;
            image->base=info->dlpi_addr;
            return 1;
        },&image);
        if (image.path.empty()) return false;
        int fd=open(image.path.c_str(),O_RDONLY|O_CLOEXEC);
        struct stat st{};
        if (fd<0) return false;
        if (fstat(fd,&st) || st.st_size<static_cast<off_t>(sizeof(Ehdr)) || st.st_size>64*1024*1024) { close(fd); return false; }
        image_.resize(st.st_size);
        size_t pos=0;
        while (pos<image_.size()) {
            auto n=read(fd,image_.data()+pos,image_.size()-pos);
            if (n<=0) { close(fd); return false; }
            pos+=n;
        }
        close(fd);
        if (!header(image_)) return false;
        base_=image.base;
        decompress();
        ready_=true;
        return true;
    }
    void release() {
        std::vector<uint8_t>().swap(image_);
        std::vector<uint8_t>().swap(debug_);
    }
    void *find(std::string_view name,bool prefix=false) const {
        auto value=lookup(image_,name,prefix);
        if (!value) value=lookup(debug_,name,prefix);
        return value ? reinterpret_cast<void *>(base_+value) : nullptr;
    }
};
