#include <jni.h>
#include <android/log.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "lsplant.hpp"
#include "dobby.h"
#include "art_symbols.hpp"



namespace {
// Payload and app-specific Java objects are initialized only after final UID.
std::vector<uint8_t> payload;
jobject loader_keep;
jobject bridge_keep;
bool attempted;
bool prepare_attempted;
bool prepared;
jfieldID path_field, elements_field, dex_field, cookie_field;
int installed;
ArtSymbols symbols;

bool failed(JNIEnv *env, const char *phase) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    __android_log_print(ANDROID_LOG_ERROR, "TrustUserCertificates", "hooks: %s failed", phase);
    return false;
}

bool cache_dex_fields(JNIEnv *env) {
    auto base = env->FindClass("dalvik/system/BaseDexClassLoader");
    auto path_class = env->FindClass("dalvik/system/DexPathList");
    auto element_class = env->FindClass("dalvik/system/DexPathList$Element");
    auto dex_class = env->FindClass("dalvik/system/DexFile");
    if (!base || !path_class || !element_class || !dex_class) return failed(env,"dex classes");
    path_field = env->GetFieldID(base,"pathList","Ldalvik/system/DexPathList;");
    elements_field = env->GetFieldID(path_class,"dexElements","[Ldalvik/system/DexPathList$Element;");
    dex_field = env->GetFieldID(element_class,"dexFile","Ldalvik/system/DexFile;");
    cookie_field = env->GetFieldID(dex_class,"mCookie","Ljava/lang/Object;");
    if (!path_field || !elements_field || !dex_field || !cookie_field) return failed(env,"dex fields");
    return true;
}

bool trust_dex(JNIEnv *env, jobject loader) {
    auto path = env->GetObjectField(loader,path_field);
    auto elements = static_cast<jobjectArray>(env->GetObjectField(path,elements_field));
    if (!elements || env->GetArrayLength(elements) == 0) return failed(env,"dex elements");
    for (jsize i=0; i<env->GetArrayLength(elements); ++i) {
        auto element = env->GetObjectArrayElement(elements,i);
        auto dex = env->GetObjectField(element,dex_field);
        auto cookie = dex ? env->GetObjectField(dex,cookie_field) : nullptr;
        if (!cookie || !lsplant::MakeDexFileTrusted(env,cookie)) return failed(env,"trusted dex");
    }
    return true;
}

bool deopt_constructors(JNIEnv *env, const char *name) {
    auto cls = env->FindClass(name);
    auto class_class = env->FindClass("java/lang/Class");
    if (!cls || !class_class) return failed(env,"deopt constructor class");
    auto get = env->GetMethodID(class_class,"getDeclaredConstructors","()[Ljava/lang/reflect/Constructor;");
    if (!get) return failed(env,"constructor enumeration");
    auto constructors = static_cast<jobjectArray>(env->CallObjectMethod(cls,get));
    if (!constructors || env->ExceptionCheck() || !env->GetArrayLength(constructors)) return failed(env,"deopt constructors");
    for (jsize i=0;i<env->GetArrayLength(constructors);++i) {
        auto constructor = env->GetObjectArrayElement(constructors,i);
        if (!constructor || !lsplant::Deoptimize(env,constructor)) return failed(env,"deopt constructor");
        env->DeleteLocalRef(constructor);
    }
    return true;
}

bool deopt(JNIEnv *env, const char *name, const char *method, const char *signature) {
    auto cls = env->FindClass(name);
    if (!cls) return failed(env,"deopt class");
    auto id = env->GetMethodID(cls,method,signature);
    if (!id) return failed(env,"deopt method");
    auto reflected = env->ToReflectedMethod(cls,id,JNI_FALSE);
    if (!reflected || !lsplant::Deoptimize(env,reflected)) return failed(env,"deoptimize");
    return true;
}
}

// Run in the selected zygote child before specialization, with unrestricted JNI.
// This initializes only ART hooks and framework reflection/DexFile primitives.
extern "C" __attribute__((visibility("default")))
int tuc_hooks_prepare(JNIEnv *env) {
    if (!env) return 0;
    if (prepare_attempted) return prepared;
    prepare_attempted = true;
    if (env->PushLocalFrame(64) != JNI_OK) { failed(env,"JNI local frame"); return 0; }
    const auto run = [&]() -> bool {
        if (!symbols.init()) { failed(env,"ART symbol file"); return false; }
        lsplant::InitInfo info{
            .inline_hooker = [](void *target,void *hook) -> void * {
                void *backup = nullptr;
                return DobbyHook(target,hook,&backup) == 0 ? backup : nullptr;
            },
            .inline_unhooker = [](void *target) { return DobbyDestroy(target) == 0; },
            .art_symbol_resolver = [](std::string_view name) { return symbols.find(name); },
            .art_symbol_prefix_resolver = [](std::string_view name) { return symbols.find(name,true); },
            .executable_memory_allocator = {},
            .executable_memory_recycler = {},
        };
        const bool initialized = lsplant::Init(env,info);
        // LSPlant uses symbol resolvers only during InitNative; retain no ART file copy.
        symbols.release();
        if (!initialized) { failed(env,"ART initialization"); return false; }
        if (!cache_dex_fields(env)) return false;
        // Reflection must run with unrestricted JNI; these classes have no user CA singleton.
        // Deoptimize callers that may contain an inlined Builder.build().
        return deopt_constructors(env,"android/security/net/config/ManifestConfigSource$DefaultConfigSource") &&
            // XML builds configs in the parser, not directly in ensureInitialized().
            deopt(env,"android/security/net/config/XmlConfigSource","parseNetworkSecurityConfig",
                "(Landroid/content/res/XmlResourceParser;)V") &&
            deopt(env,"android/security/net/config/XmlConfigSource","ensureInitialized","()V");
    };
    prepared = run();
    if (env->ExceptionCheck()) { failed(env,"preparation"); prepared = false; }
    env->PopLocalFrame(nullptr);
    return prepared;
}

// Returns the subset of requested flags that was installed; zero means no hook.
// The caller must keep this library loaded after any call, including a failed init.
extern "C" __attribute__((visibility("default")))
int tuc_hooks_install(JNIEnv *env, const void *dex, size_t size, uint8_t flags) {
    if (!prepared || !env || !dex || size < 8 || size > 4*1024*1024 || !flags || (flags & ~7)) return 0;
    if (attempted) return installed;
    attempted = true;
    if (env->PushLocalFrame(64) != JNI_OK) { failed(env,"JNI local frame"); return 0; }
    const auto run = [&]() -> int {
        payload.assign(static_cast<const uint8_t *>(dex),static_cast<const uint8_t *>(dex)+size);
        auto class_loader = env->FindClass("java/lang/ClassLoader");
        auto memory_loader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        if (!class_loader || !memory_loader) { failed(env,"class loader"); return 0; }
        auto system_method = env->GetStaticMethodID(class_loader,"getSystemClassLoader","()Ljava/lang/ClassLoader;");
        auto constructor = env->GetMethodID(memory_loader,"<init>","(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto load_class = env->GetMethodID(class_loader,"loadClass","(Ljava/lang/String;)Ljava/lang/Class;");
        if (!system_method || !constructor || !load_class) { failed(env,"loader methods"); return 0; }
        auto parent = env->CallStaticObjectMethod(class_loader,system_method);
        auto buffer = env->NewDirectByteBuffer(payload.data(),payload.size());
        auto loader = env->NewObject(memory_loader,constructor,buffer,parent);
        if (!loader || env->ExceptionCheck() || !trust_dex(env,loader)) { failed(env,"payload loader"); return 0; }
        auto name = env->NewStringUTF("HookBridge");
        auto bridge_class = static_cast<jclass>(env->CallObjectMethod(loader,load_class,name));
        if (!bridge_class || env->ExceptionCheck()) { failed(env,"HookBridge class"); return 0; }
        auto bridge_constructor = env->GetMethodID(bridge_class,"<init>","(I)V");
        auto active_method = env->GetMethodID(bridge_class,"activeFlags","()I");
        auto target_method = env->GetMethodID(bridge_class,"target","()Ljava/lang/reflect/Method;");
        auto callback_method = env->GetMethodID(bridge_class,"callback","()Ljava/lang/reflect/Method;");
        auto set_backup = env->GetMethodID(bridge_class,"setBackup","(Ljava/lang/reflect/Method;)V");
        if (!bridge_constructor || !active_method || !target_method || !callback_method || !set_backup) { failed(env,"HookBridge methods"); return 0; }
        auto bridge = env->NewObject(bridge_class,bridge_constructor,static_cast<jint>(flags));
        if (!bridge || env->ExceptionCheck()) { failed(env,"HookBridge initialization"); return 0; }
        auto active = env->CallIntMethod(bridge,active_method) & flags;
        if (!active || env->ExceptionCheck()) return 0;
        auto target = env->CallObjectMethod(bridge,target_method);
        auto callback = env->CallObjectMethod(bridge,callback_method);
        if (!target || !callback || env->ExceptionCheck()) { failed(env,"HookBridge reflection"); return 0; }
        auto backup = lsplant::Hook(env,target,bridge,callback);
        if (!backup || env->ExceptionCheck()) { failed(env,"Builder.build hook"); return 0; }
        env->CallVoidMethod(bridge,set_backup,backup);
        if (env->ExceptionCheck()) {
            (void)lsplant::UnHook(env,target);
            failed(env,"backup method");
            return 0;
        }
        loader_keep = env->NewGlobalRef(loader);
        bridge_keep = env->NewGlobalRef(bridge);
        __android_log_print(ANDROID_LOG_INFO,"TrustUserCertificates","hooks installed requested=%u active=%d",flags,active);
        return active;
    };
    installed = run();
    if (env->ExceptionCheck()) failed(env,"installation");
    env->PopLocalFrame(nullptr);
    return installed;
}
