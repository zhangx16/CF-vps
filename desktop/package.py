#!/usr/bin/env python3
"""Build the Windows portable release; never package user data or node links."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
VERSION = '0.2.0-beta.2'
PROGRAM = 'CF-VPS-Desktop'
XRAY_VERSION = 'v26.10.31'
XRAY_SHA256 = '2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a'

def main():
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    stage = dist / PROGRAM
    if stage.exists():
        shutil.rmtree(stage)
    (stage / 'core').mkdir(parents=True)
    env = dict(os.environ, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0')
    subprocess.run([os.environ.get('GO', 'go'), 'build', '-trimpath', '-ldflags', '-H windowsgui -s -w', '-o', str(stage / (PROGRAM + '.exe')), '.'], cwd=ROOT, env=env, check=True)
    archive = dist / 'Xray-windows-64.zip'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != XRAY_SHA256:
        with urllib.request.urlopen(f'https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/Xray-windows-64.zip', timeout=120) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != XRAY_SHA256:
        raise RuntimeError('Upstream Xray SHA256 mismatch')
    with zipfile.ZipFile(archive) as source:
        for name in ['xray.exe', 'LICENSE']:
            (stage / 'core' / name).write_bytes(source.read(name))
    for name in ['README.md', 'THIRD_PARTY_NOTICES.md']:
        shutil.copyfile(ROOT / name, stage / name)
    shutil.copyfile(ROOT / 'LICENSE', stage / 'LICENSE')
    target = dist / f'{PROGRAM}-{VERSION}-windows-amd64.zip'
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(stage.rglob('*')):
            if path.is_file():
                output.write(path, str(path.relative_to(dist)))
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (dist / (target.name + '.sha256')).write_text(f'{digest}  {target.name}\n', encoding='ascii')
    print(target)
    print('SHA256:', digest)

if __name__ == '__main__':
    main()
