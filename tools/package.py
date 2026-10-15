"""Package only installable module files; never ship source trees or local settings."""
from pathlib import Path
import sys
import zipfile

build = Path(sys.argv[1])
root = Path(__file__).resolve().parent.parent
version = next(line.split('=', 1)[1] for line in (root / 'module.prop').read_text().splitlines() if line.startswith('version='))
assert version and all(char.isalnum() or char in '.-_' for char in version)
output = root / '.artifacts' / f'TrustUserCertificates-{version}.zip'
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name in ('module.prop', 'customize.sh', 'service.sh', 'action.sh', 'manage.sh', 'global.sh', 'LICENSE'):
        archive.write(root / name, name)
    for directory in ('webroot', 'META-INF'):
        for path in sorted((root / directory).rglob('*')):
            if path.is_file() and 'app-icons' not in path.relative_to(root).parts:
                archive.write(path, path.relative_to(root))
    archive.write(build / 'cert-tool.jar', 'cert-tool.jar')
    for abi in ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'):
        archive.write(build / 'libs' / abi / 'libtrustusercerts.so', f'zygisk/{abi}.so')
with zipfile.ZipFile(output) as archive:
    assert archive.testzip() is None
    assert len([name for name in archive.namelist() if name.startswith('zygisk/')]) == 4
print(output)
