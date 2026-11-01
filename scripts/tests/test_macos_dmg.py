"""Real macOS disk-image roundtrip; synthetic ad-hoc app, no app launch."""
import plistlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_macos_common_signing import load_signer


@unittest.skipUnless(sys.platform == "darwin", "native macOS disk image tools")
class NativeMacosDmgTest(unittest.TestCase):
    def setUp(self):
        self.signer = load_signer()
        temporary = tempfile.TemporaryDirectory(prefix="nelomai-native-dmg-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / "input/Nelomai.app"
        (self.app / "Contents/MacOS").mkdir(parents=True)
        shutil.copyfile("/usr/bin/true", self.app / "Contents/MacOS/nelomai")
        (self.app / "Contents/MacOS/nelomai").chmod(0o755)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "ru.nelomai.client", "CFBundleExecutable": "nelomai",
            "CFBundlePackageType": "APPL", "CFBundleName": "Nelomai"}))
        resource = self.app / "Contents/Resources/runtime/payload"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(b"exact signed embedded resource")
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(self.app)],
                       check=True, capture_output=True)
        self.work = self.root / "work"
        self.work.mkdir()
        self.image = self.root / "nelomai-0.4.0-macos-aarch64.dmg"
        self.addCleanup(self.detach_owned_image)

    def detach_owned_image(self):
        for item in self.signer.image_attachments(self.image):
            device = item["system-entities"][0]["dev-entry"]
            subprocess.run(["/usr/bin/hdiutil", "detach", device], check=True, capture_output=True)

    def test_native_dmg_preserves_signed_app_and_applications_link(self):
        before = self.signer.snapshot(self.app)
        self.signer.build_dmg(self.app, self.image, self.work, "0.4.0")
        self.assertTrue(self.image.is_file(), "native DMG was not created")
        self.assertEqual(self.signer.snapshot(self.app), before)
        info = plistlib.loads(subprocess.check_output(["/usr/bin/hdiutil", "imageinfo", "-plist", str(self.image)]))
        self.assertEqual(info["Format"], "UDZO")
        mount = None
        try:
            attached = plistlib.loads(subprocess.check_output(
                ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(self.image)]))
            mount, = [Path(entry["mount-point"]) for entry in attached["system-entities"] if "mount-point" in entry]
            self.assertEqual(os.readlink(mount / "Applications"), "/Applications")
            self.assertEqual((mount / "Nelomai.app/Contents/Resources/runtime/payload").read_bytes(),
                             b"exact signed embedded resource")
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(mount / "Nelomai.app")],
                           check=True, capture_output=True)
        finally:
            if mount is not None and mount.is_mount():
                subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)], check=True, capture_output=True)
        mounted = plistlib.loads(subprocess.check_output(["/usr/bin/hdiutil", "info", "-plist"]))
        self.assertNotIn(str(self.image), [entry.get("image-path") for entry in mounted["images"]])

    def test_changed_app_is_rejected_and_owned_image_is_detached(self):
        self.signer.build_dmg(self.app, self.image, self.work, "0.4.0")
        expected = self.signer.snapshot(self.app)
        expected["Contents/Resources/runtime/payload"] = (0o644, "0" * 64)
        with self.assertRaisesRegex(ValueError, "content differs"):
            self.signer.verify_dmg(self.image, expected)
        self.assertEqual(self.signer.image_attachments(self.image), [])

    def test_partial_attach_failure_detaches_only_this_image(self):
        self.signer.build_dmg(self.app, self.image, self.work, "0.4.0")
        run = self.signer.run
        def interrupted(*command, **kwargs):
            result = run(*command, **kwargs)
            if command[:2] == ("/usr/bin/hdiutil", "attach"):
                raise RuntimeError("interrupted after real readonly attach")
            return result
        with patch.object(self.signer, "run", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                self.signer.verify_dmg(self.image, self.signer.snapshot(self.app))
        self.assertEqual(self.signer.image_attachments(self.image), [])
