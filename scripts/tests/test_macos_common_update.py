"""Run the actual installer in a temp tree; mock only root/OS trust boundaries."""
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MacosCommonUpdateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nelomai-common-update-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.install_root = self.root / "protected/common"
        self.destination = self.install_root / "Nelomai.app"
        self.destination.mkdir(parents=True)
        (self.destination / "previous-marker").write_text("old")
        (self.destination / "Contents/Resources/runtime").mkdir(parents=True)
        self.source = self.root / "input/Nelomai.app"
        (self.source / "Contents/Resources/runtime").mkdir(parents=True)
        (self.source / "Contents/MacOS").mkdir(parents=True)
        self.executable(self.source / "Contents/MacOS/nelomai-app", '''#!/bin/sh
test "$1" = --verify-runtime-layout || exit 90
test -d "$2" && test -d "$3" || exit 91
test "${REJECT_LAYOUT:-0}" = 0 || exit 92
printf 'layout\\n' >> "$EVENTS"
''')
        (self.source / "new-marker").write_text("new")
        (self.source / "new-marker").chmod(0o666)
        (self.source / "Contents/MacOS/nelomai-app").chmod(0o777)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.executable(self.bin / "id", "#!/bin/sh\nprintf '0\\n'\n")
        self.executable(self.bin / "chown", '''#!/bin/sh
test "$1" = -R && test "$2" = root:wheel || exit 93
test -f "$3/new-marker" || exit 94
printf 'ownership\\n' >> "$EVENTS"
''')
        # No actual ownership changes, privilege elevation or system paths.
        self.executable(self.bin / "install", '''#!/bin/sh
if [ "$1" = -d ]; then
  shift 7
  /bin/mkdir -p "$@"
else
  test "$1" = -o && test "$2" = root && test "$3" = -g && test "$4" = wheel || exit 95
  /bin/cp "$7" "$8"
  /bin/chmod "$6" "$8"
fi
''')
        self.executable(self.bin / "ditto", '#!/bin/sh\n/bin/cp -R "$1" "$2"\n')
        self.executable(self.bin / "codesign", '''#!/bin/sh
test "$1" = --verify && test "$2" = --strict || exit 96
test "${REJECT_SIGNATURE:-0}" = 0 || exit 97
printf 'signature\\n' >> "$EVENTS"
''')
        self.executable(self.bin / "mv", '''#!/bin/sh
if [ "${FAIL_ACTIVATION:-0}" = 1 ] && [ -f "$1/new-marker" ]; then exit 98; fi
/bin/mv "$@"
''')
        script = (ROOT / "crates/unix-service/install/install-common-macos.sh").read_text()
        script = script.replace("/Library/Application Support/Nelomai", str(self.root / "protected"))
        script = script.replace("/usr/bin/ditto", str(self.bin / "ditto"))
        script = script.replace("/usr/bin/codesign", str(self.bin / "codesign"))
        self.script = self.root / "installer.sh"
        self.script.write_text(script)
        self.events = self.root / "events"

    @staticmethod
    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)

    def archive(self, extra=None):
        archive = self.root / "verified update 'quoted'.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(self.source, arcname="Nelomai.app")
            if extra:
                header = tarfile.TarInfo(extra)
                header.size = 4
                tar.addfile(header, io.BytesIO(b"evil"))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def run_installer(self, args, *, umask=-1, **settings):
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", EVENTS=str(self.events), **settings)
        return subprocess.run(["/bin/sh", str(self.script), *map(str, args)],
                              env=env, capture_output=True, text=True, timeout=10, umask=umask)

    def assert_previous_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "previous-marker").read_text(), "old")
        self.assertFalse((self.destination / "new-marker").exists())

    def test_verified_archive_installs_protected_bundle_and_retains_previous(self):
        result = self.run_installer(self.archive())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "new-marker").read_text(), "new")
        self.assertEqual(self.events.read_text().splitlines(), ["ownership", "layout", "signature"])
        self.assertEqual(len(list(self.install_root.glob(".install.*/previous.app/previous-marker"))), 1)
        self.assertFalse(list(self.install_root.glob(".install.*/update.tar.gz")))
        for path in self.destination.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o022, str(path))

    def test_existing_bundle_install_remains_supported(self):
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.destination / "new-marker").exists())

    def test_archive_permissions_do_not_inherit_authorizing_users_umask(self):
        # Public bundle directories must remain traversable after root takes
        # ownership; the private staging parent must not become public.
        for path in [self.source, *self.source.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
        archive = self.archive()
        for mask in (0o077, 0o027, 0o022, 0o000):
            with self.subTest(umask=oct(mask)):
                result = self.run_installer(archive, umask=mask)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for path in [self.destination, *self.destination.rglob("*")]:
                    expected = 0o755 if path.is_dir() or path.name == "nelomai-app" else 0o644
                    self.assertEqual(path.stat().st_mode & 0o777, expected, str(path))
                for staging in self.install_root.glob(".install.*"):
                    self.assertEqual(staging.stat().st_mode & 0o777, 0o700)
                self.assertEqual((self.source / "new-marker").stat().st_mode & 0o777, 0o666)

    def test_changed_or_invalid_digest_never_activates(self):
        archive, _ = self.archive()
        for digest in ["0" * 64, "x" * 64, "", "abcd"]:
            with self.subTest(digest=digest):
                self.assert_previous_preserved(self.run_installer([archive, digest]))
        self.assertFalse(self.events.exists())

    def test_archive_rejects_unexpected_paths_before_activation(self):
        for name in ["outside", "../escaped", "Nelomai.app/../../escaped", "/absolute"]:
            with self.subTest(name=name):
                self.assert_previous_preserved(self.run_installer(self.archive(name)))
        self.assertFalse((self.root / "escaped").exists())
        self.assertFalse(self.events.exists())

    def test_symlink_in_verified_archive_is_not_installed(self):
        (self.source / "link").symlink_to(self.root)
        self.assert_previous_preserved(self.run_installer(self.archive()))

    def test_failed_layout_or_signature_keeps_old_bundle(self):
        for flag in ["REJECT_LAYOUT", "REJECT_SIGNATURE"]:
            with self.subTest(flag=flag):
                self.assert_previous_preserved(self.run_installer(self.archive(), **{flag: "1"}))

    def test_failed_activation_restores_previous_bundle(self):
        self.assert_previous_preserved(self.run_installer(self.archive(), FAIL_ACTIVATION="1"))

    @unittest.skipUnless(sys.platform == "darwin", "AppleScript requires macOS")
    def test_authorization_handoff_quotes_archive_and_preserves_bundle_mode(self):
        script = (ROOT / "crates/unix-service/install/install-common-macos.applescript").read_text()
        # Exercise the real argument builder; do not ask for or execute elevation.
        script = script.replace("do shell script commandText with administrator privileges", "return commandText")
        apple_script = self.root / "handoff.applescript"
        apple_script.write_text(script)
        for args in [
            ["/protected/install.sh", "/tmp/app's bundle.app"],
            ["/protected/install.sh", "/tmp/archive' ; touch nope.tar.gz", "a" * 64],
        ]:
            with self.subTest(args=args):
                result = subprocess.run(["/usr/bin/osascript", str(apple_script), *args],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(shlex.split(result.stdout), ["/bin/sh", *args])
        result = subprocess.run(["/usr/bin/osascript", str(apple_script), "only-one"],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
