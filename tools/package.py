"""Package the installable module and corresponding source; exclude local settings."""
from pathlib import Path
import sys
import zipfile

build = Path(sys.argv[1])
root = Path(__file__).resolve().parent.parent
version = next(line.split('=', 1)[1] for line in (root / 'module.prop').read_text().splitlines() if line.startswith('version='))
assert version and all(char.isalnum() or char in '.-_' for char in version)
output = root / '.artifacts' / f'tuc-next-{version}.zip'
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name in ('module.prop', 'customize.sh', 'service.sh', 'action.sh', 'manage.sh', 'global.sh', 'LICENSE', 'NOTICE'):
        archive.write(root / name, name)
    for directory in ('webroot', 'META-INF'):
        for path in sorted((root / directory).rglob('*')):
            if path.is_file() and 'app-icons' not in path.relative_to(root).parts:
                archive.write(path, path.relative_to(root))
    archive.write(build / 'cert-tool.jar', 'cert-tool.jar')
    archive.write(root / 'LICENSE', 'webroot/license.txt')
    archive.write(root / 'NOTICE', 'webroot/notice.txt')
    for abi in ('arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'):
        archive.write(build / 'libs' / abi / 'libtrustusercerts.so', f'zygisk/{abi}.so')
with zipfile.ZipFile(output) as archive:
    assert archive.testzip() is None
    assert len([name for name in archive.namelist() if name.startswith('zygisk/')]) == 4
print(output)
source = root / '.artifacts' / f'tuc-next-{version}-source.zip'
with zipfile.ZipFile(source, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name in ('.gitignore', 'README.md', 'changelog.md', 'LICENSE', 'NOTICE', 'module.prop',
                 'customize.sh', 'service.sh', 'action.sh', 'manage.sh', 'global.sh'):
        archive.write(root / name, name)
    for directory in ('.github', 'META-INF', 'native', 'tools', 'tests', 'webroot'):
        for path in sorted((root / directory).rglob('*')):
            if path.is_file() and not {'app-icons', '__pycache__'}.intersection(path.relative_to(root).parts):
                archive.write(path, path.relative_to(root))
with zipfile.ZipFile(source) as archive:
    assert archive.testzip() is None
print(source)
