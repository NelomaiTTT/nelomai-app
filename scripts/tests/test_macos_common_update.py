"""Run the actual installer in a temp tree; mock only root/OS trust boundaries."""
import hashlib
import io
import os
import plistlib
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
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
        resources = self.source / "Contents/Resources"
        dispatcher = resources / "dispatcher/1/nelomai-unix-service"
        dispatcher.parent.mkdir(parents=True)
        self.service_root = self.root / "protected/service"
        self.service_root.mkdir(parents=True)
        (self.service_root / "container-manifest.json").write_text("previous-pointer")
        self.plist = self.root / "protected/service.plist"
        self.plist.write_text("previous-plist")
        self.executable(dispatcher, '''#!/bin/sh
set -eu
case "$1" in
  install-layout)
    test "$#" = 4 && test "$4" = 501 || exit 80
    test "$2" = "$DESTINATION/Contents/Resources/runtime" || exit 81
    test "$3" = "$DESTINATION/Contents/MacOS/nelomai-app" || exit 82
    test -f "$DESTINATION/new-marker" || exit 83
    test "${REJECT_HELPER:-0}" = 0 || exit 84
    printf 'helper:501\\n' >> "$EVENTS"
    mkdir -p "$SERVICE_ROOT/releases/new/dispatcher/1"
    printf new-pointer > "$SERVICE_ROOT/container-manifest.json"
    printf '%s/releases/new/dispatcher/1/nelomai-unix-service\\n' "$SERVICE_ROOT"
    ;;
  rollback-layout)
    test "$2" = new-pointer && test "$3" = previous-pointer || exit 85
    test "${REJECT_ROLLBACK:-0}" = 0 || exit 91
    printf '%s' "$3" > "$SERVICE_ROOT/container-manifest.json"
    printf 'helper-rollback\\n' >> "$EVENTS"
    ;;
  *) exit 86 ;;
esac
''')
        helper_installer = (ROOT / "crates/unix-service/install/install-macos.sh").read_text()
        helper_installer = helper_installer.replace("/Library/PrivilegedHelperTools/$LABEL", str(self.service_root))
        helper_installer = helper_installer.replace("/Library/LaunchDaemons/$LABEL.plist", str(self.plist))
        (resources / "install-macos.sh").write_text(helper_installer)
        (self.source / "Contents/MacOS").mkdir(parents=True)
        self.executable(self.source / "Contents/MacOS/nelomai-app", '''#!/bin/sh
test "$1" = --verify-runtime-layout || exit 90
test -d "$2" || exit 91
if [ "$#" = 3 ]; then test -d "$3" || exit 91; fi
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
if [ "$1" = root:wheel ]; then test "$2" = "$SERVICE_PLIST"; exit; fi
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
        self.executable(self.bin / "xattr", '''#!/bin/sh
test "$1" = -dr && test "$2" = com.apple.quarantine || exit 96
test "${REJECT_QUARANTINE_NORMALIZATION:-0}" = 0 || exit 97
''' + ('exec /usr/bin/xattr "$@"\n' if sys.platform == "darwin" else 'exit 0\n'))
        self.executable(self.bin / "mv", '''#!/bin/sh
if [ "${FAIL_ACTIVATION:-0}" = 1 ] && [ -f "$1/new-marker" ]; then exit 98; fi
case "$1" in
  */previous.app) if [ "${FAIL_BUNDLE_RESTORE:-0}" = 1 ]; then exit 99; fi ;;
esac
/bin/mv "$@"
''')
        self.executable(self.bin / "launchctl", '''#!/bin/sh
case "$1" in
  bootout) test "$2" = system/ru.nelomai.tunnel || exit 87 ;;
  bootstrap)
    test "$2" = system && test "$3" = "$SERVICE_PLIST" || exit 88
    if [ "${REJECT_BOOTSTRAP:-0}" = 1 ] && grep -q new/dispatcher "$3"; then exit 89; fi
    printf 'service-ready\\n' >> "$EVENTS"
    ;;
  *) exit 90 ;;
esac
''')
        script = (ROOT / "crates/unix-service/install/install-common-macos.sh").read_text()
        script = script.replace("/Library/Application Support/Nelomai", str(self.root / "protected"))
        script = script.replace("/usr/bin/ditto", str(self.bin / "ditto"))
        script = script.replace("/usr/bin/codesign", str(self.bin / "codesign"))
        script = script.replace("/usr/bin/xattr", str(self.bin / "xattr"))
        script = script.replace("/usr/bin/hdiutil", str(self.bin / "hdiutil"))
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

    def run_installer(self, args, *, umask=-1, owner_uid="501", **settings):
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", EVENTS=str(self.events),
                   DESTINATION=str(self.destination), SERVICE_ROOT=str(self.service_root),
                   SERVICE_PLIST=str(self.plist), **settings)
        return subprocess.run(["/bin/sh", str(self.script), owner_uid, *map(str, args)],
                              env=env, capture_output=True, text=True, timeout=10, umask=umask)

    def assert_previous_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "previous-marker").read_text(), "old")
        self.assertFalse((self.destination / "new-marker").exists())

    def test_verified_archive_installs_protected_bundle_and_retains_previous(self):
        result = self.run_installer(self.archive())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "new-marker").read_text(), "new")
        self.assertEqual(self.events.read_text().splitlines(),
                         ["ownership", "layout", "signature", "helper:501", "service-ready"])
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "new-pointer")
        self.assertEqual(len(list(self.install_root.glob(".install.*/previous.app/previous-marker"))), 1)
        self.assertFalse(list(self.install_root.glob(".install.*/update.tar.gz")))
        for path in self.destination.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o022, str(path))

    def dmg(self):
        image = self.root / "verified update 'quoted'.dmg"
        image.write_bytes(b"authenticated disk image fixture")
        self.executable(self.bin / "hdiutil", """#!/bin/sh
set -eu
case "$1" in
  verify)
    test "${REJECT_IMAGE:-0}" = 0 || exit 77
    printf 'image-verify\\n' >> "$EVENTS" ;;
  attach)
    test "$2" = -readonly && test "$3" = -nobrowse && test "$4" = -noautoopen && test "$5" = -mountpoint || exit 78
    /bin/cp -R "$DMG_SOURCE" "$6/Nelomai.app"
    /bin/ln -s /Applications "$6/Applications"
    printf 'image-attach\\n' >> "$EVENTS"
    test "${REJECT_ATTACH:-0}" = 0 || exit 79 ;;
  detach)
    printf 'image-detach\\n' >> "$EVENTS"
    test "${REJECT_DETACH:-0}" = 0 || exit 80 ;;
  *) exit 81 ;;
esac
""")
        return image, hashlib.sha256(image.read_bytes()).hexdigest()

    def test_dmg_is_hashed_before_mount_and_detached_before_activation(self):
        args = self.dmg()
        result = self.run_installer(args, DMG_SOURCE=str(self.source))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.events.read_text().splitlines()
        self.assertEqual(events[:3], ["image-verify", "image-attach", "image-detach"])
        self.assertLess(events.index("image-detach"), events.index("helper:501"))
        self.assertTrue((self.destination / "new-marker").exists())
        self.assertFalse(list(self.install_root.glob(".install.*/update.dmg")))

    def test_dmg_hash_failure_never_calls_hdiutil(self):
        image, _ = self.dmg()
        self.assert_previous_preserved(self.run_installer([image, "0" * 64], DMG_SOURCE=str(self.source)))
        self.assertFalse(self.events.exists())

    def test_dmg_failure_preserves_previous_and_detach_is_required(self):
        args = self.dmg()
        for failure in ["REJECT_IMAGE", "REJECT_ATTACH", "REJECT_DETACH"]:
            with self.subTest(failure=failure):
                self.events.unlink(missing_ok=True)
                self.assert_previous_preserved(self.run_installer(args, DMG_SOURCE=str(self.source), **{failure:"1"}))
                events = self.events.read_text().splitlines() if self.events.exists() else []
                self.assertNotIn("helper:501", events)
                if failure != "REJECT_IMAGE":
                    self.assertIn("image-detach", events)
        # Same authenticated download can be retried after a failed mount/detach.
        self.assertEqual(self.run_installer(args, DMG_SOURCE=str(self.source)).returncode, 0)

    def test_dmg_rejects_links_inside_app_and_detaches_on_copy_failure(self):
        args = self.dmg()
        link = self.source / "Contents/escape"
        link.symlink_to(self.root)
        result = self.run_installer(args, DMG_SOURCE=str(self.source))
        self.assert_previous_preserved(result)
        self.assertIn("image-detach", self.events.read_text())
        link.unlink()
        self.events.unlink()
        self.executable(self.bin / "ditto", "#!/bin/sh\nexit 79\n")
        result = self.run_installer(args, DMG_SOURCE=str(self.source))
        self.assert_previous_preserved(result)
        self.assertIn("image-detach", self.events.read_text())
        self.assertNotIn("helper:501", self.events.read_text())

    def test_interrupted_dmg_copy_detaches_preserves_previous_and_can_retry(self):
        args = self.dmg()
        self.executable(self.bin / "ditto", '#!/bin/sh\nprintf "copy-ready\\n" >> "$EVENTS"\nsleep 10\n/bin/cp -R "$1" "$2"\n')
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", EVENTS=str(self.events),
                   DESTINATION=str(self.destination), SERVICE_ROOT=str(self.service_root),
                   SERVICE_PLIST=str(self.plist), DMG_SOURCE=str(self.source))
        process = subprocess.Popen(["/bin/sh", str(self.script), "501", *map(str,args)], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self.events.exists() and "copy-ready" in self.events.read_text():
                    break
                time.sleep(.02)
            self.assertIn("copy-ready", self.events.read_text())
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.assert_previous_preserved(result)
            self.assertIn("image-detach", self.events.read_text())
            self.assertNotIn("helper:501", self.events.read_text())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)
        self.executable(self.bin / "ditto", '#!/bin/sh\n/bin/cp -R "$1" "$2"\n')
        self.assertEqual(self.run_installer(args, DMG_SOURCE=str(self.source)).returncode, 0)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS disk image")
    def test_native_dmg_mount_copy_detach_leaves_no_installer_image(self):
        image = self.root / "native.dmg"
        image_root = self.root / "dmg-root"
        image_root.mkdir()
        shutil.copytree(self.source, image_root / "Nelomai.app")
        (image_root / "Applications").symlink_to("/Applications")
        subprocess.run(["/usr/bin/hdiutil", "create", "-fs", "HFS+", "-format", "UDZO", "-nospotlight", "-srcfolder", str(image_root), str(image)], check=True, capture_output=True)
        # Disk Arbitration on this host rejects custom mountpoints on removable
        # volumes. Keep all bytes on SSD, let macOS choose its normal read-only
        # mount, and map only this fixture's private mountpoint to it. The real
        # production mount under /Library (and root elevation) is not simulated
        # as verified by this test; copy, checksums and detach are native here.
        self.executable(self.bin / "hdiutil", f"#!{sys.executable}\n" + """
import os, pathlib, plistlib, subprocess, sys
args=sys.argv[1:]
if args[0]=='attach':
    assert args[1:5]==['-readonly','-nobrowse','-noautoopen','-mountpoint']
    point=pathlib.Path(args[5])
    result=subprocess.run(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-noautoopen','-plist',args[6]],capture_output=True)
    if result.returncode: sys.exit(result.returncode)
    entries=plistlib.loads(result.stdout)['system-entities']
    mounts=[entry['mount-point'] for entry in entries if 'mount-point' in entry]
    assert len(mounts)==1
    point.rmdir(); point.symlink_to(mounts[0])
elif args[0]=='detach':
    point=pathlib.Path(args[1])
    result=subprocess.run(['/usr/bin/hdiutil','detach',str(point.resolve())])
    if result.returncode: sys.exit(result.returncode)
    point.unlink(); point.mkdir()
else:
    sys.exit(subprocess.run(['/usr/bin/hdiutil',*args]).returncode)
""")
        result = self.run_installer([image, hashlib.sha256(image.read_bytes()).hexdigest()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.destination / "new-marker").exists())
        self.assertFalse(list(self.install_root.glob(".install.*/update.dmg")))
        for mount in self.install_root.glob(".install.*/mount"):
            self.assertFalse(os.path.ismount(mount), "installer image still mounted")

    def test_existing_bundle_install_remains_supported(self):
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.destination / "new-marker").exists())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine metadata")
    def test_downloaded_bundle_keeps_source_quarantine_out_of_protected_install(self):
        # Removing the protected-copy policy must reproduce the remote startup
        # failure's prerequisite. Exercise real ditto and xattrs, not a copy mock.
        self.executable(self.bin / "ditto", '#!/bin/sh\nexec /usr/bin/ditto "$@"\n')
        quarantine = "00c1;6ae7b1f3;Telegram;"
        for attribute, value in [("com.apple.quarantine", quarantine),
                                 ("com.nelomai.test-metadata", "keep")]:
            subprocess.run(["/usr/bin/xattr", "-w", attribute, value, str(self.source)], check=True)
        source_executable = self.source / "Contents/MacOS/nelomai-app"
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", quarantine,
                        str(source_executable)], check=True)
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        source_marker = subprocess.check_output(
            ["/usr/bin/xattr", "-p", "com.apple.quarantine", str(self.source)], text=True)
        self.assertEqual(source_marker.strip(), quarantine)
        destination_attributes = subprocess.check_output(
            ["/usr/bin/xattr", str(self.destination)], text=True).splitlines()
        self.assertNotIn("com.apple.quarantine", destination_attributes)
        installed_executable = self.destination / "Contents/MacOS/nelomai-app"
        self.assertNotIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(installed_executable)], text=True).splitlines())
        self.assertEqual(subprocess.check_output(
            ["/usr/bin/xattr", "-p", "com.apple.quarantine", str(source_executable)],
            text=True).strip(), quarantine)
        metadata = subprocess.check_output(
            ["/usr/bin/xattr", "-p", "com.nelomai.test-metadata", str(self.destination)], text=True)
        self.assertEqual(metadata.strip(), "keep")
        self.assertEqual((self.destination / "new-marker").read_bytes(), b"new")

    def test_failed_quarantine_normalization_never_replaces_previous_bundle(self):
        self.assert_previous_preserved(self.run_installer(
            [self.source], REJECT_QUARANTINE_NORMALIZATION="1"))
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "previous-pointer")

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine metadata")
    def test_rejected_signature_keeps_quarantine_in_retained_staging(self):
        self.executable(self.bin / "ditto", '#!/bin/sh\nexec /usr/bin/ditto "$@"\n')
        quarantine = "00c1;6ae7b1f3;Telegram;"
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", quarantine,
                        str(self.source)], check=True)
        self.assert_previous_preserved(self.run_installer([self.source], REJECT_SIGNATURE="1"))
        staged, = self.install_root.glob(".install.*/Nelomai.app")
        # macOS may update the quarantine flags when the layout verifier runs;
        # failed validation must not remove the marker from retained staging.
        self.assertIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(staged)], text=True).splitlines())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine metadata")
    def test_metadata_repair_preserves_installed_version_inode_and_service(self):
        (self.source / "installed-version").write_text("0.4.1")
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stderr)
        inode = self.destination.stat().st_ino
        backups = list(self.install_root.glob(".install.*"))
        events = self.events.read_text()
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "00c1;6ae7b1f3;Telegram;",
                        str(self.destination)], check=True)
        result = self.run_installer([self.source, "--repair-download-metadata"])
        self.assertNotEqual(result.returncode, 0)
        for flag in ("REJECT_LAYOUT", "REJECT_SIGNATURE", "REJECT_QUARANTINE_NORMALIZATION"):
            with self.subTest(rejection=flag):
                result = self.run_installer([self.destination, "--repair-download-metadata"], **{flag: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.destination.stat().st_ino, inode)
                self.assertIn("com.apple.quarantine", subprocess.check_output(
                    ["/usr/bin/xattr", str(self.destination)], text=True).splitlines())
        events = self.events.read_text()
        result = self.run_installer([self.destination, "--repair-download-metadata"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.stat().st_ino, inode)
        self.assertEqual((self.destination / "installed-version").read_text(), "0.4.1")
        self.assertEqual(list(self.install_root.glob(".install.*")), backups)
        self.assertEqual(self.events.read_text(), events + "layout\nsignature\n")
        self.assertNotIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(self.destination)], text=True).splitlines())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine metadata and SIGKILL")
    def test_interrupted_metadata_repair_retains_newer_bundle_and_retries(self):
        (self.source / "installed-version").write_text("0.4.1")
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stderr)
        inode = self.destination.stat().st_ino
        late = self.destination / "zzz-late-resource"
        late.write_bytes(b"resource after the interrupt boundary")
        for path in (self.destination, self.destination / "Contents", late):
            subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "00c1;6ae7b1f3;Telegram;", str(path)], check=True)
        barrier = self.root / "metadata-child-cleaned"
        self.executable(self.bin / "xattr", '''#!/bin/sh
set -eu
/usr/bin/xattr "$@"
if [ "$3" = "$DESTINATION/Contents" ]; then
  : > "$METADATA_BARRIER"
  /bin/sleep 0.5
fi
''')
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", EVENTS=str(self.events),
                   DESTINATION=str(self.destination), SERVICE_ROOT=str(self.service_root),
                   SERVICE_PLIST=str(self.plist), METADATA_BARRIER=str(barrier))
        process = subprocess.Popen(["/bin/sh", str(self.script), "501", str(self.destination), "--repair-download-metadata"],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not barrier.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(barrier.exists(), "metadata repair did not reach the interrupt boundary")
            process.kill()
            process.communicate(timeout=3)
            self.assertEqual(process.returncode, -signal.SIGKILL)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)
        self.assertEqual(self.destination.stat().st_ino, inode)
        self.assertEqual((self.destination / "installed-version").read_text(), "0.4.1")
        self.assertIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(self.destination)], text=True).splitlines())
        self.assertIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(late)], text=True).splitlines())
        self.executable(self.bin / "xattr", '#!/bin/sh\nexec /usr/bin/xattr "$@"\n')
        result = self.run_installer([self.destination, "--repair-download-metadata"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.stat().st_ino, inode)
        self.assertEqual((self.destination / "installed-version").read_text(), "0.4.1")
        self.assertNotIn("com.apple.quarantine", subprocess.check_output(
            ["/usr/bin/xattr", str(late)], text=True).splitlines())

    def test_first_install_activates_helper_before_success(self):
        shutil.rmtree(self.destination)
        result = self.run_installer([self.source])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.destination / "new-marker").exists())
        self.assertEqual(self.events.read_text().splitlines(),
                         ["ownership", "layout", "signature", "helper:501", "service-ready"])

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
                    expected = 0o755 if path.is_dir() or path.name in ("nelomai-app", "nelomai-unix-service") else 0o644
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

    def test_invalid_original_user_is_rejected_before_any_installation(self):
        for uid in ["0", "", "root", "501; echo injected", "-1"]:
            with self.subTest(uid=uid):
                self.assert_previous_preserved(self.run_installer([self.source], owner_uid=uid))
        self.assertFalse(self.events.exists())

    def test_failed_helper_install_restores_common_bundle(self):
        self.assert_previous_preserved(self.run_installer(self.archive(), REJECT_HELPER="1"))
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "previous-pointer")
        self.assertEqual(self.plist.read_text(), "previous-plist")

    def test_first_install_does_not_publish_common_when_helper_install_fails(self):
        shutil.rmtree(self.destination)
        result = self.run_installer([self.source], REJECT_HELPER="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(len(list(self.install_root.glob(".install.*/Nelomai.app/new-marker"))), 1)

    def test_missing_dispatcher_never_replaces_previous_bundle(self):
        (self.source / "Contents/Resources/dispatcher/1/nelomai-unix-service").unlink()
        self.assert_previous_preserved(self.run_installer([self.source]))

    def test_failed_helper_activation_rolls_back_service_and_common_together(self):
        self.assert_previous_preserved(self.run_installer(self.archive(), REJECT_BOOTSTRAP="1"))
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "previous-pointer")
        self.assertEqual(self.plist.read_text(), "previous-plist")
        self.assertEqual(self.events.read_text().splitlines(),
                         ["ownership", "layout", "signature", "helper:501",
                          "helper-rollback", "service-ready"])

    def test_failed_common_restore_retains_both_bundles_for_recovery(self):
        result = self.run_installer(self.archive(), REJECT_BOOTSTRAP="1", FAIL_BUNDLE_RESTORE="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(len(list(self.install_root.glob(".install.*/previous.app/previous-marker"))), 1)
        self.assertEqual(len(list(self.install_root.glob(".install.*/Nelomai.app/new-marker"))), 1)
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "previous-pointer")

    def test_failed_service_rollback_reports_cleanup_and_retains_bundles(self):
        result = self.run_installer(self.archive(), REJECT_BOOTSTRAP="1", REJECT_ROLLBACK="1")
        self.assert_previous_preserved(result)
        self.assertIn("Dispatcher activation rollback requires cleanup", result.stderr)
        self.assertEqual((self.service_root / "container-manifest.json").read_text(), "new-pointer")
        self.assertEqual(len(list(self.install_root.glob(".install.*/Nelomai.app/new-marker"))), 1)

    @unittest.skipUnless(sys.platform == "darwin", "AppleScript requires macOS")
    def test_authorization_handoff_quotes_archive_and_preserves_bundle_mode(self):
        script = (ROOT / "crates/unix-service/install/install-common-macos.applescript").read_text()
        # Exercise the real argument builder; do not ask for or execute elevation.
        script = script.replace("do shell script commandText with administrator privileges", "return commandText")
        apple_script = self.root / "handoff.applescript"
        apple_script.write_text(script)
        for args in [
            ["/protected/install.sh", "501", "/tmp/app's bundle.app"],
            ["/protected/install.sh", "501", "/tmp/archive' ; touch nope.tar.gz", "a" * 64],
            ["/protected/install.sh", "501", "/protected/Nelomai.app", "--repair-download-metadata"],
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
