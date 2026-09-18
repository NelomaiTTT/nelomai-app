#!/usr/bin/env python3
"""Stage a signed runtime ZIP as the latest-only desktop container resources.

Consume the packager's final ZIP (including final macOS ad-hoc signatures).
Never copy pre-signing inputs into the installed container. No publication,
installation, elevation, or implicit key discovery is performed here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def stage(artifact,output,signing_key):
    if output.exists():raise ValueError('immutable bundle output already exists')
    spec=importlib.util.spec_from_file_location('desktop_packager',Path(__file__).with_name('package-runtime-artifact.py'))
    packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(packager)
    if signing_key.is_symlink() or signing_key.stat().st_size!=32:raise ValueError('explicit raw Ed25519 key required')
    key=Ed25519PrivateKey.from_private_bytes(signing_key.read_bytes())
    manifest_path=artifact/'runtime-manifest-v1.json'
    if manifest_path.stat().st_size>1024*1024:raise ValueError('manifest size limit')
    raw=manifest_path.read_bytes()
    signature=(artifact/'runtime-manifest-v1.sig').read_bytes()
    key.public_key().verify(signature,b'nelomai-runtime-manifest-v1\0'+raw)
    manifest=json.loads(raw)
    if canonical(manifest)!=raw:raise ValueError('noncanonical runtime manifest')
    if manifest['format_version']!=1 or manifest['contract_version']!=1:raise ValueError('unsupported runtime contract')
    version=manifest['runtime_version']
    expected=json.loads((Path(__file__).resolve().parents[1]/'src-tauri/tauri.conf.json').read_text())['version']
    if version!=expected:raise ValueError('runtime and common container versions differ')
    entries={};aliases=set();total=0
    for item in manifest['files']:
        name=item['path'];alias=packager.portable_alias(name)
        if alias in aliases:raise ValueError('duplicate runtime path')
        aliases.add(alias)
        if item['role'] not in ('executable','shared_library','resource','license','metadata'):raise ValueError('invalid runtime role')
        size=item['size_bytes'];total+=size
        if not 0<size<=512*1024*1024 or total>2*1024*1024*1024 or len(aliases)>4096:raise ValueError('runtime size limit')
        entries[name]=item
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.desktop-stage-',dir=output.parent) as temporary:
        staged=Path(temporary)/'bundle'
        root=staged/'runtime';slot=root/'engines/latest'/version
        with zipfile.ZipFile(artifact/'runtime.zip') as archive:
            infos=archive.infolist()
            if len(infos)!=len(entries) or {info.filename for info in infos}!=entries.keys():raise ValueError('archive differs from signed file set')
            for info in infos:
                item=entries[info.filename]
                if info.file_size!=item['size_bytes'] or info.is_dir():raise ValueError('archive file size mismatch')
                mode=(info.external_attr>>16)&0o170000
                if mode not in (0,0o100000):raise ValueError('nonregular archive entry')
                path=slot/info.filename;path.parent.mkdir(parents=True,exist_ok=True)
                digest=hashlib.sha256();written=0
                with archive.open(info) as source,path.open('xb') as destination:
                    while chunk:=source.read(1024*1024):
                        written+=len(chunk)
                        if written>item['size_bytes']:raise ValueError('archive expands beyond signed size')
                        digest.update(chunk);destination.write(chunk)
                if digest.hexdigest()!=item['sha256'] or written!=item['size_bytes']:raise ValueError('archive hash mismatch')
                path.chmod(0o755 if item['role']=='executable' else 0o644)
        service='nelomai-windows-service.exe' if manifest['platform']=='windows' else 'nelomai-unix-service'
        runtime='nelomai-runtime.exe' if manifest['platform']=='windows' else 'nelomai-runtime'
        if manifest['platform']=='macos':
            candidates=entries.keys() & {'nelomai-runtime','Nelomai','Nelomai.app/Contents/MacOS/Nelomai'}
            if len(candidates)!=1:raise ValueError('missing or ambiguous macOS runtime executable')
            runtime=candidates.pop()
        for name in (service,runtime):
            if name not in entries or entries[name]['role']!='executable':raise ValueError('runtime executable missing')
        dispatcher=staged/'dispatcher/1'/service;dispatcher.parent.mkdir(parents=True)
        shutil.copyfile(slot/service,dispatcher);dispatcher.chmod(0o755)
        container=dict(format_version=1,container_version=version,release_set_id='desktop-latest-'+version+'-'+manifest['source_commit'],minimum_runtime_contract=1,maximum_runtime_contract=1,slots=[dict(slot='latest',manifest=manifest)])
        body=canonical(container)
        (root/'container-manifest-v1.json').write_bytes(body)
        (root/'container-manifest-v1.sig').write_bytes(key.sign(b'nelomai-container-manifest-v1\0'+body))
        staged.rename(output)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('artifact','output','signing-key'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();stage(args.artifact,args.output,args.signing_key)

if __name__=='__main__':main()
