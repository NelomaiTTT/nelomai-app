import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

SCRIPT=Path(__file__).resolve().parents[1]/'stage-desktop-runtime.py'

class RuntimeStagingTest(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='nelomai-staging-test-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.artifact=self.root/'artifact';self.artifact.mkdir()
        self.key=Ed25519PrivateKey.generate();self.key_path=self.root/'local-key'
        self.key_path.write_bytes(self.key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        files=[]
        with zipfile.ZipFile(self.artifact/'runtime.zip','w') as archive:
            for name,data,role in [('nelomai-runtime',b'signed executable fixture','executable'),('nelomai-unix-service',b'signed dispatcher fixture','executable'),('webview/index.html',b'<html>compiled UI fixture</html>','resource')]:
                info=zipfile.ZipInfo(name);info.external_attr=(0o100755 if role=='executable' else 0o100644)<<16
                archive.writestr(info,data)
                files.append(dict(path=name,size_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),role=role))
        manifest=dict(format_version=1,runtime_version='0.2.19',source_commit='a'*40,platform='linux',architecture='x86_64',contract_version=1,files=files)
        self.raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
        (self.artifact/'runtime-manifest-v1.json').write_bytes(self.raw)
        (self.artifact/'runtime-manifest-v1.sig').write_bytes(self.key.sign(b'nelomai-runtime-manifest-v1\0'+self.raw))
    def run_stage(self):
        return subprocess.run([sys.executable,str(SCRIPT),'--artifact',str(self.artifact),'--output',str(self.root/'bundle'),'--signing-key',str(self.key_path)],capture_output=True,text=True)
    def test_staging_uses_exact_signed_archive_bytes_and_emits_latest_only_container(self):
        result=self.run_stage();self.assertEqual(result.returncode,0,result.stderr)
        root=self.root/'bundle/runtime'
        raw=(root/'container-manifest-v1.json').read_bytes()
        self.key.public_key().verify((root/'container-manifest-v1.sig').read_bytes(),b'nelomai-container-manifest-v1\0'+raw)
        manifest=json.loads(raw)
        self.assertEqual([slot['slot'] for slot in manifest['slots']],['latest'])
        self.assertEqual(manifest['slots'][0]['manifest'],json.loads(self.raw))
        for item in manifest['slots'][0]['manifest']['files']:
            path=root/'engines/latest/0.2.19'/item['path']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),item['sha256'])
            self.assertEqual(path.stat().st_mode&0o777,0o755 if item['role']=='executable' else 0o644)
        self.assertEqual((self.root/'bundle/dispatcher/1/nelomai-unix-service').read_bytes(),b'signed dispatcher fixture')
        self.assertNotEqual(self.run_stage().returncode,0,'immutable bundle must not be overwritten')
    def test_tampered_or_extra_archive_file_is_never_staged(self):
        with zipfile.ZipFile(self.artifact/'runtime.zip','a') as archive:archive.writestr('extra',b'unadmitted')
        self.assertNotEqual(self.run_stage().returncode,0)
        self.assertFalse((self.root/'bundle').exists())
    def test_wrong_manifest_signature_is_never_staged(self):
        (self.artifact/'runtime-manifest-v1.sig').write_bytes(bytes(64))
        self.assertNotEqual(self.run_stage().returncode,0)
        self.assertFalse((self.root/'bundle').exists())

    def macos_fixture(self, ambiguous=False, runtime='Nelomai'):
        manifest=json.loads(self.raw);manifest['platform']='macos';manifest['architecture']='aarch64'
        with zipfile.ZipFile(self.artifact/'runtime.zip') as archive:
            files=[(item,archive.read(item.filename)) for item in archive.infolist()]
        with zipfile.ZipFile(self.artifact/'runtime.zip','w') as archive:
            for info,data in files:
                if info.filename=='nelomai-runtime':
                    if ambiguous:archive.writestr(info,data)
                    info.filename=runtime
                archive.writestr(info,data)
        original=manifest['files'][0]
        if ambiguous:manifest['files'].append(dict(original))
        original['path']=runtime
        raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
        (self.artifact/'runtime-manifest-v1.json').write_bytes(raw)
        (self.artifact/'runtime-manifest-v1.sig').write_bytes(self.key.sign(b'nelomai-runtime-manifest-v1\0'+raw))

    def test_macos_product_named_runtime_is_staged_with_signed_bytes_and_execute_mode(self):
        self.macos_fixture()
        result=self.run_stage();self.assertEqual(result.returncode,0,result.stderr)
        executable=self.root/'bundle/runtime/engines/latest/0.2.19/Nelomai'
        self.assertEqual(executable.read_bytes(),b'signed executable fixture')
        self.assertEqual(executable.stat().st_mode&0o777,0o755)
        self.assertFalse(executable.with_name('nelomai-runtime').exists())

    def test_macos_ambiguous_runtime_names_are_rejected(self):
        self.macos_fixture(ambiguous=True)
        self.assertNotEqual(self.run_stage().returncode,0)
        self.assertFalse((self.root/'bundle').exists())

    def test_macos_bundle_runtime_is_staged_without_rewriting_signed_bytes(self):
        runtime='Nelomai.app/Contents/MacOS/Nelomai'
        self.macos_fixture(runtime=runtime)
        result=self.run_stage();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/'bundle/runtime/engines/latest/0.2.19'/runtime).read_bytes(),
                         b'signed executable fixture')

    def test_macos_bundle_and_legacy_executable_are_rejected_together(self):
        self.macos_fixture(ambiguous=True,runtime='Nelomai.app/Contents/MacOS/Nelomai')
        self.assertNotEqual(self.run_stage().returncode,0)

if __name__=='__main__':unittest.main()
