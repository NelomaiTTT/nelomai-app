"""Real archive/index handling; mock only native Security/codesign operations."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
import plistlib
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
PIN = "12" * 20
DR = 'identifier "ru.nelomai.client" and certificate leaf = H"' + PIN + '"'


def load_signer():
    path = ROOT / "scripts/sign-macos-common-package.py"
    if not path.exists():
        raise AssertionError("stable common signing implementation is missing")
    spec = importlib.util.spec_from_file_location("macos_signer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommonSigningTest(unittest.TestCase):
    def setUp(self):
        self.signer = load_signer()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.root / "fixture/Nelomai.app"
        for name, data in {
            "Contents/MacOS/nelomai": b"unsigned-common",
            "Contents/Resources/runtime/stable": b"immutable-stable",
            "Contents/Resources/dispatcher/1/service": b"immutable-dispatcher",
            "Contents/_CodeSignature/CodeResources": b"old-seal",
        }.items():
            p = self.app / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        (self.app / "Contents/MacOS/nelomai").chmod(0o755)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ru.nelomai.client", "CFBundleExecutable": "nelomai"}))
        self.source = self.root / "input"
        (self.source / "shipping").mkdir(parents=True)
        self.archive = self.source / "shipping/nelomai-0.3.2-macos-aarch64.app.tar.gz"
        self.args = SimpleNamespace(input=self.source, output=self.root / "output", work=self.root / "work",
            source_sha="a" * 40, release_set_sha256="b" * 64, mode="sign_candidate", certificate_sha1=PIN)
        self.env = {"NELOMAI_MACOS_SIGNING_P12_BASE64": base64.b64encode(b"test-p12").decode(),
                    "NELOMAI_MACOS_SIGNING_P12_PASSWORD": "test-password"}
        # Image creation is a native boundary; separate native tests mount a real
        # image. Here preserve the input bytes so producer ordering is observable.
        self.addCleanup(patch.stopall)
        patch.object(self.signer, "build_dmg", side_effect=self.fake_dmg, create=True).start()
        self.pack()

    def pack(self):
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.app, arcname="Nelomai.app")
        self.index = dict(source_sha="a" * 40, release_set_sha256="b" * 64, mode=self.args.mode,
            platform="macos", architecture="aarch64", native_payloads="verified", full_acceptance="UNRUN",
            packages={"shipping": dict(name=self.archive.name,
                sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(), size_bytes=self.archive.stat().st_size)})
        self.save_index()

    def save_index(self):
        (self.source / "package-digests.json").write_text(json.dumps(self.index))

    def fake_sign(self, app, pin, work, environment):
        self.assertEqual(pin, PIN)
        (app / "Contents/MacOS/nelomai").write_bytes(b"signed-common")
        (app / "Contents/_CodeSignature/CodeResources").write_bytes(b"new-seal")

    def fake_dmg(self, app, destination, work, version):
        destination.write_text(json.dumps({
            "common": (app / "Contents/MacOS/nelomai").read_text(), "version": version}))

    def process(self, sign=None):
        with patch.object(self.signer, "sign_bundle", side_effect=sign or self.fake_sign), \
             patch.object(self.signer, "verify_signature", return_value=None):
            self.signer.process(self.args, self.env)

    def test_signed_output_digest_and_nested_bytes(self):
        old = self.archive.read_bytes()
        self.process()
        index = json.loads((self.args.output / "package-digests.json").read_text())
        output = self.args.output / "shipping" / self.archive.name
        self.assertNotEqual(output.read_bytes(), old)
        self.assertEqual(self.archive.read_bytes(), old)
        self.assertEqual(index["packages"]["shipping"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(index["macos_common_signature"], dict(identifier="ru.nelomai.client",
            certificate_sha1=PIN, designated_requirement=DR))
        with tarfile.open(output) as tar:
            self.assertEqual(tar.extractfile("Nelomai.app/Contents/Resources/runtime/stable").read(), b"immutable-stable")
            self.assertEqual(tar.extractfile("Nelomai.app/Contents/MacOS/nelomai").read(), b"signed-common")
        self.assertEqual(sorted(p.name for p in self.args.output.iterdir()), ["package-digests.json", "shipping"])

    def test_manual_dmg_contains_the_final_signed_common_and_is_indexed(self):
        self.process()
        name = "nelomai-0.3.2-macos-aarch64.dmg"
        image = self.args.output / "shipping" / name
        self.assertTrue(image.is_file(), "manual-install DMG is missing")
        self.assertEqual(json.loads(image.read_text()), {"common": "signed-common", "version": "0.3.2"})
        index = json.loads((self.args.output / "package-digests.json").read_text())
        self.assertEqual(index["packages"]["dmg"], dict(
            name=name, sha256=hashlib.sha256(image.read_bytes()).hexdigest(), size_bytes=image.stat().st_size))

    def test_dmg_failure_never_publishes_partial_signed_package(self):
        with patch.object(self.signer, "build_dmg", side_effect=RuntimeError("image failed")):
            with self.assertRaises(RuntimeError):
                self.process()
        self.assertFalse(self.args.output.exists())

    def test_manual_image_must_match_exact_indexed_name_and_bytes(self):
        self.process()
        name = "nelomai-0.3.2-macos-aarch64.dmg"
        index = json.loads((self.args.output / "package-digests.json").read_text())
        image = self.signer.require_dmg(index, self.args.output, name)
        for field in ("name", "sha256", "size_bytes"):
            record = index["packages"]["dmg"]
            original = record[field]
            record[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.signer.require_dmg(index, self.args.output, name)
            record[field] = original
        image.write_bytes(b"tampered image")
        with self.assertRaises(ValueError):
            self.signer.require_dmg(index, self.args.output, name)

    def test_missing_credentials_and_pin_never_fall_back(self):
        for env, pin in (({}, PIN), (self.env, ""), (self.env, "NotAFingerprint")):
            with self.subTest(pin=pin, credentials=bool(env)):
                self.args.certificate_sha1 = pin
                with self.assertRaises(ValueError):
                    self.signer.process(self.args, env)
                self.assertFalse(self.args.output.exists())

    def test_build_only_is_keyless_and_byte_preserving(self):
        self.args.mode = "build_only"
        self.args.certificate_sha1 = ""
        self.pack()
        with patch.object(self.signer, "sign_bundle", side_effect=AssertionError("key imported")):
            self.signer.process(self.args, {})
        self.assertEqual((self.args.output / "shipping" / self.archive.name).read_bytes(), self.archive.read_bytes())

    def test_wrong_source_or_archive_hash_rejected_before_signing(self):
        for field in ("source_sha", "release_set_sha256", "mode", "platform", "architecture"):
            original = self.index[field]
            self.index[field] = "wrong"
            self.save_index()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.process()
            self.index[field] = original
        self.save_index()
        self.archive.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.process()

    def test_existing_output_not_modified(self):
        self.args.output.mkdir()
        marker = self.args.output / "keep"
        marker.write_text("untouched")
        with self.assertRaises(ValueError):
            self.process()
        self.assertEqual(marker.read_text(), "untouched")

    def test_nested_mutation_rejected_without_output(self):
        for name in ("Contents/Resources/runtime/stable", "Contents/Resources/dispatcher/1/service", "Contents/Info.plist"):
            def mutate(app, *args):
                (app / name).write_bytes(b"changed")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.process(mutate)
            self.assertFalse(self.args.output.exists())

    def test_signature_metadata_permissions_cannot_become_user_inaccessible(self):
        for name in ("Contents/_CodeSignature", "Contents/_CodeSignature/CodeResources"):
            def restrict(app, *args):
                (app / name).chmod(0o700)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.process(restrict)
            self.assertFalse(self.args.output.exists())

    def test_restrictive_umask_preserves_archive_and_installed_directory_permissions(self):
        for path in (self.app, *self.app.rglob("*")):
            path.chmod(0o755 if path.is_dir() or path.name == "nelomai" else 0o644)
        self.pack()
        original = self.archive.read_bytes()
        for mask in (0o077, 0o027, 0o022, 0):
            with self.subTest(umask=oct(mask)):
                self.args.output = self.root / f"output-{mask}"
                old = os.umask(mask)
                try:
                    self.process()
                finally:
                    unchanged_mask = os.umask(old)
                self.assertEqual(unchanged_mask, mask, "signing must not change process umask")
                archive = self.args.output / "shipping" / self.archive.name
                with tarfile.open(archive) as tar:
                    for member in tar.getmembers():
                        expected = 0o755 if member.isdir() or member.name.endswith("/MacOS/nelomai") else 0o644
                        self.assertEqual(member.mode, expected, member.name)
                installed = self.root / f"installed-{mask}"
                installed.mkdir()
                subprocess.run(["/bin/sh", "-c",
                    'umask 022; tar -xzf "$1" --no-same-owner --no-same-permissions -C "$2"',
                    "test", str(archive), str(installed)], check=True)
                for path in (installed / "Nelomai.app", *(installed / "Nelomai.app").rglob("*")):
                    expected = 0o755 if path.is_dir() or path.name == "nelomai" else 0o644
                    self.assertEqual(path.stat().st_mode & 0o777, expected, str(path))
                self.assertEqual(self.archive.read_bytes(), original)

    def test_directory_filter_retains_safe_modes_but_not_group_other_write(self):
        directory = self.app / "Contents/Resources/runtime"
        for mode, expected in ((0o750, 0o750), (0o555, 0o555), (0o777, 0o755)):
            with self.subTest(mode=oct(mode)):
                directory.chmod(mode)
                self.pack()
                extracted, _ = self.signer.extract(self.archive, self.root / f"extract-{mode}")
                self.assertEqual((extracted / "Contents/Resources/runtime").stat().st_mode & 0o777, expected)

    def test_links_and_traversal_rejected(self):
        for name, kind in (("Nelomai.app/../escape", tarfile.REGTYPE),
                           ("/absolute", tarfile.REGTYPE), ("Nelomai.app/link", tarfile.SYMTYPE),
                           ("Nelomai.app/hard", tarfile.LNKTYPE)):
            with tarfile.open(self.archive, "w:gz") as tar:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.linkname = "/tmp/elsewhere"
                tar.addfile(item)
            self.index["packages"]["shipping"].update(sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                                                     size_bytes=self.archive.stat().st_size)
            self.save_index()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.process()

    def test_wrong_identifier_rejected(self):
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "other", "CFBundleExecutable": "nelomai"}))
        self.pack()
        with self.assertRaises(ValueError):
            self.process()

    def test_wrong_designated_requirement_rejected(self):
        for requirement in ('cdhash H"abcd"', DR.replace(PIN, "34" * 20), DR.replace("ru.nelomai.client", "other")):
            with patch.object(self.signer, "run", return_value="designated => " + requirement), \
                 self.subTest(requirement=requirement), self.assertRaises(ValueError):
                self.signer.verify_signature(self.app, PIN)

    def test_signing_failure_restores_search_list_and_removes_secrets(self):
        search = ["/test/login.keychain-db"]
        deleted = []
        def run(*cmd, **kwargs):
            cmd = tuple(str(c) for c in cmd)
            if cmd[:2] == ("/usr/bin/security", "create-keychain"):
                Path(cmd[-1]).touch()
            if cmd[:3] == ("/usr/bin/security", "list-keychains", "-d"):
                if "-s" in cmd:
                    search[:] = cmd[cmd.index("-s") + 1:]
                    return ""
                return '\n'.join('"' + p + '"' for p in search)
            if cmd[:2] == ("/usr/bin/security", "delete-keychain"):
                deleted.append(cmd[-1])
            if cmd[0] == "/usr/bin/codesign":
                raise RuntimeError("synthetic signing failure")
            return ""
        self.args.work.mkdir()
        with patch.object(self.signer, "run", side_effect=run), self.assertRaises(RuntimeError):
            self.signer.sign_bundle(self.app, PIN, self.args.work, self.env)
        self.assertEqual(search, ["/test/login.keychain-db"])
        self.assertEqual(len(deleted), 1)
        self.assertNotEqual(deleted[0], search[0])
        self.assertFalse(any(self.args.work.rglob("*.p12")))

    def test_command_failure_does_not_expose_secrets(self):
        with self.assertRaises(RuntimeError) as error:
            self.signer.run("/usr/bin/false", "private-password")
        self.assertNotIn("private-password", str(error.exception))

    def test_native_failure_and_cleanup_failures_are_attributed_in_order_without_secrets(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        self.env["NELOMAI_MACOS_SIGNING_P12_PASSWORD"] = marker
        self.args.work.mkdir()
        def native(command, **kwargs):
            if command[1] == "create-keychain":
                Path(command[-1]).touch()
            code = 0
            if command[1] == "import":
                code = 42
            elif command[1] == "list-keychains" and "-s" in command:
                code = 19
            elif command[1] == "delete-keychain":
                code = 17
            return subprocess.CompletedProcess(command, code, '"/' + marker + '"', marker)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(self.signer.subprocess, "run", side_effect=native):
            with self.assertRaisesRegex(RuntimeError, "exit 17") as error:
                self.signer.sign_bundle(self.app, PIN, self.args.work, self.env)
        log = err.getvalue()
        events = ["operation=security-import event=failed status=42",
                  "stage=keychain-cleanup event=entered",
                  "operation=security-restore-search event=failed status=19",
                  "operation=security-delete-keychain event=failed status=17",
                  "stage=keychain-cleanup event=failed", "stage=sign-bundle event=failed"]
        for event in events:
            self.assertIn(event, log)
        positions = [log.index(event) for event in events]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn(marker, out.getvalue() + log + str(error.exception))
        self.assertFalse(any(self.args.work.rglob("*.p12")))

    def test_native_timeout_and_oserror_are_distinct_without_exception_or_output_leaks(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        self.args.work.mkdir()
        for failure, event in ((subprocess.TimeoutExpired([marker], 60, output=marker, stderr=marker), "timeout"),
                               (OSError(marker), "oserror")):
            def native(command, **kwargs):
                if command[1] == "import":
                    raise failure
                if command[1] == "create-keychain":
                    Path(command[-1]).touch()
                return subprocess.CompletedProcess(command, 0, '"/' + marker + '"', "")
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(event=event), redirect_stdout(out), redirect_stderr(err), \
                 patch.object(self.signer.subprocess, "run", side_effect=native):
                with self.assertRaises(RuntimeError) as error:
                    self.signer.sign_bundle(self.app, PIN, self.args.work, self.env)
                self.assertIn("operation=security-import event=" + event, err.getvalue())
                self.assertIn("stage=keychain-cleanup event=completed", err.getvalue())
                self.assertNotIn(marker, out.getvalue() + err.getvalue() + str(error.exception))

    def test_unknown_command_name_is_never_used_as_a_diagnostic_label(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(self.signer.subprocess, "run",
                return_value=subprocess.CompletedProcess([marker], 23, marker, marker)):
            with self.assertRaises(RuntimeError) as error:
                self.signer.run("/" + marker, marker)
        self.assertIn("operation=native event=failed status=23", err.getvalue())
        self.assertNotIn(marker, out.getvalue() + err.getvalue() + str(error.exception))

    def test_diagnostics_reject_unknown_labels_and_non_numeric_status(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        class UntrustedLabel(str):
            def __str__(self):
                return marker
        err = io.StringIO()
        with redirect_stderr(err):
            self.signer.diagnostic("operation", marker, "failed", 23)
            self.signer.diagnostic(marker, "native", "failed", 23)
            self.signer.diagnostic("operation", "native", marker, 23)
            self.signer.diagnostic("operation", UntrustedLabel("native"), "failed", 23)
            self.signer.diagnostic("operation", "native", "failed", marker)
            self.signer.diagnostic("operation", "native", "failed", 2 ** 100)
        self.assertNotIn(marker, err.getvalue())
        self.assertEqual(err.getvalue().splitlines(), ["macos-sign operation=native event=failed"] * 2)

    def test_real_subprocess_exit_and_timeout_are_attributed_without_captured_output(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        for program, timeout, event in (("import sys; print(sys.argv[1]); print(sys.argv[1], file=sys.stderr); sys.exit(23)",
                                         10, "failed status=23"),
                                        ("import sys, time; print(sys.argv[1], flush=True); time.sleep(10)",
                                         0.1, "timeout")):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(event=event), redirect_stdout(out), redirect_stderr(err):
                with self.assertRaises(RuntimeError) as error:
                    self.signer.run(sys.executable, "-c", program, marker, timeout=timeout)
                self.assertIn("operation=native event=" + event, err.getvalue())
                self.assertNotIn(marker, out.getvalue() + err.getvalue() + str(error.exception))

    def test_main_native_failure_keeps_output_unpublished_and_allows_clean_rerun(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        def native(command, **kwargs):
            if command[1] == "create-keychain":
                Path(command[-1]).touch()
            code = 29 if command[1] == "import" else 0
            return subprocess.CompletedProcess(command, code, '"/' + marker + '"', "")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
             patch.object(self.signer.subprocess, "run", side_effect=native), \
             patch.object(self.signer.argparse.ArgumentParser, "parse_args", return_value=self.args), \
             patch.dict(os.environ, self.env):
            with self.assertRaises(SystemExit) as error:
                self.signer.main()
        self.assertEqual(error.exception.code, 1)
        self.assertIn("operation=security-import event=failed status=29", err.getvalue())
        self.assertIn("stage=keychain-cleanup event=completed", err.getvalue())
        self.assertIn("stage=process event=failed", err.getvalue())
        self.assertNotIn(marker, out.getvalue() + err.getvalue())
        self.assertFalse(self.args.output.exists())
        self.assertEqual(list(self.args.work.iterdir()), [])
        with redirect_stderr(io.StringIO()):
            self.process()
        self.assertTrue(self.args.output.is_dir())

    def test_main_attributes_logical_validation_without_publishing_or_exception_text(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        self.index["packages"]["shipping"]["name"] = marker
        self.save_index()
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
             patch.object(self.signer.argparse.ArgumentParser, "parse_args", return_value=self.args), \
             patch.dict(os.environ, self.env):
            with self.assertRaises(SystemExit) as error:
                self.signer.main()
        self.assertEqual(error.exception.code, 1)
        self.assertIn("stage=input-validation event=failed", err.getvalue())
        self.assertIn("stage=main event=failed", err.getvalue())
        self.assertIn("macOS common signing failed; no package published", err.getvalue())
        self.assertNotIn(marker, out.getvalue() + err.getvalue())
        self.assertFalse(self.args.output.exists())

    def test_protected_content_failure_is_attributed_before_output_publication(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        protected = self.app / "Contents/Resources" / marker
        protected.write_bytes(b"original")
        self.pack()
        def mutate(app, *args):
            (app / "Contents/Resources" / marker).write_bytes(b"changed")
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(ValueError):
            self.process(mutate)
        self.assertIn("stage=bundle-content event=failed", err.getvalue())
        self.assertNotIn(marker, err.getvalue())
        self.assertFalse(self.args.output.exists())

    def test_success_reports_completed_stages_and_stream_failure_does_not_change_result(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.process()
        self.assertIn("stage=input-validation event=completed", err.getvalue())
        self.assertIn("stage=publish-output event=completed", err.getvalue())
        self.assertIn("stage=process event=completed", err.getvalue())
        class BrokenStream:
            def write(self, text):
                raise OSError("diagnostic stream unavailable")
        self.args.output = self.root / "second-output"
        with redirect_stderr(BrokenStream()):
            self.process()
        self.assertTrue(self.args.output.is_dir())
        primary = ValueError("primary failure")
        self.args.output = self.root / "failed-output"
        with redirect_stderr(BrokenStream()), self.assertRaises(ValueError) as error:
            self.process(lambda *args: (_ for _ in ()).throw(primary))
        self.assertIs(error.exception, primary)
        self.assertFalse(self.args.output.exists())

    def test_partial_dmg_attach_timeout_is_logged_before_authoritative_cleanup_failure(self):
        marker = "INJECTED_SECRET_DO_NOT_LOG"
        queries = 0
        def native(command, **kwargs):
            nonlocal queries
            if command[1] == "info":
                queries += 1
                images = [] if queries == 1 else [{"image-path": str(self.archive.resolve()),
                    "system-entities": [{"dev-entry": "/dev/disk99"}]}]
                return subprocess.CompletedProcess(command, 0, plistlib.dumps({"images": images}).decode(), "")
            if command[1] == "attach":
                raise subprocess.TimeoutExpired([marker], 180, output=marker, stderr=marker)
            if command[1] == "detach":
                return subprocess.CompletedProcess(command, 24, marker, marker)
            raise AssertionError("unexpected native operation")
        err = io.StringIO()
        with redirect_stderr(err), patch.object(self.signer.subprocess, "run", side_effect=native):
            with self.assertRaisesRegex(RuntimeError, "exit 24") as error:
                self.signer.verify_dmg(self.archive, {})
        log = err.getvalue()
        self.assertIn("operation=hdiutil-attach event=timeout", log)
        self.assertIn("stage=dmg-cleanup event=entered", log)
        self.assertLess(log.index("operation=hdiutil-attach event=timeout"),
                        log.index("stage=dmg-cleanup event=entered"))
        self.assertIn("operation=hdiutil-detach event=failed status=24", log)
        self.assertIn("stage=dmg-cleanup event=failed", log)
        self.assertNotIn(marker, log + str(error.exception))

    @unittest.skipUnless(os.environ.get("NELOMAI_TEST_NATIVE_SIGNING") == "1", "isolated native signing opt-in")
    def test_native_two_builds_keep_requirement_and_preserve_nested_payload(self):
        # Own synthetic bundles/certificate/keychain only. Never run an installer
        # or access application items in the user's login keychain.
        original_search = self.signer.run("/usr/bin/security", "list-keychains", "-d", "user")
        config = self.root / "certificate.cnf"
        config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=code\n"
                          "[dn]\nCN=Nelomai isolated test\n[code]\nbasicConstraints=critical,CA:false\n"
                          "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n")
        def command(*args):
            return subprocess.run(args, check=True, capture_output=True, text=True).stdout
        key, cert, p12 = (self.root / name for name in ("test.key", "test.pem", "test.p12"))
        command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-config", str(config), "-keyout", str(key), "-out", str(cert))
        command("openssl", "pkcs12", "-export", "-inkey", str(key), "-in", str(cert), "-out", str(p12),
                "-passout", "pass:isolated-test", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1")
        pin = command("openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha1").strip().split("=")[1].replace(":", "").lower()
        self.args.certificate_sha1 = pin
        environment = dict(NELOMAI_MACOS_SIGNING_P12_BASE64=base64.b64encode(p12.read_bytes()).decode(),
                           NELOMAI_MACOS_SIGNING_P12_PASSWORD="isolated-test")
        hashes, requirements = [], []
        try:
            for revision in (1, 2):
                source = self.root / "main.c"
                source.write_text(f'int main(void) {{ return {revision}; }}\n')
                command("clang", str(source), "-o", str(self.app / "Contents/MacOS/nelomai"))
                self.pack()
                self.args.output = self.root / f"native-output-{revision}"
                self.signer.process(self.args, environment)
                index = json.loads((self.args.output / "package-digests.json").read_text())
                requirements.append(index["macos_common_signature"]["designated_requirement"])
                hashes.append(index["packages"]["shipping"]["sha256"])
            self.assertEqual(requirements[0], requirements[1])
            self.assertNotEqual(hashes[0], hashes[1])
        finally:
            key.unlink(missing_ok=True)
            p12.unlink(missing_ok=True)
            self.assertEqual(self.signer.run("/usr/bin/security", "list-keychains", "-d", "user"), original_search)


if __name__ == "__main__":
    unittest.main()
