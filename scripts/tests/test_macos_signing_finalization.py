import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests.test_macos_common_signing import ROOT, PIN, DR

spec = importlib.util.spec_from_file_location("finalizer", ROOT / "scripts/finalize-release-candidate.py")
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)


class MacosFinalizationTest(unittest.TestCase):
    def check(self, index, mode="sign_candidate", pin=PIN):
        self.assertTrue(hasattr(finalizer, "verify_macos_common_signature"), "missing common signing finalization gate")
        return finalizer.verify_macos_common_signature(index, mode, pin)

    def test_release_requires_exact_pinned_identity(self):
        metadata = dict(identifier="ru.nelomai.client", certificate_sha1=PIN, designated_requirement=DR)
        self.assertEqual(self.check({"macos_common_signature": metadata}), metadata)
        for field in metadata:
            wrong = copy.deepcopy(metadata)
            wrong[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check({"macos_common_signature": wrong})
        with self.assertRaises(ValueError):
            self.check({})
        with self.assertRaises(ValueError):
            self.check({"macos_common_signature": metadata}, pin="")

    def test_build_only_needs_no_release_identity(self):
        self.assertIsNone(self.check({}, mode="build_only", pin=""))

    def test_image_changed_during_copy_never_reaches_signer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "packages/macos"
            (folder / "shipping").mkdir(parents=True)
            archive = folder / "shipping" / finalizer.gates.PACKAGE_NAMES["macos"]
            archive.write_bytes(b"verified archive fixture")
            image = folder / "shipping" / finalizer.gates.MACOS_DMG_NAME
            image.write_bytes(b"verified DMG fixture")
            (folder / "package-digests.json").write_text(json.dumps(dict(
                source_sha="a" * 40, release_set_sha256="b" * 64, mode="build_only", platform="macos",
                architecture="aarch64", packages={kind: dict(name=path.name,
                    sha256=finalizer.verifier.digest(path), size_bytes=path.stat().st_size)
                    for kind, path in (("shipping", archive), ("dmg", image))})))
            argv = ["finalize", "--mode", "build_only", "--source-sha", "a" * 40, "--release-set-sha256", "b" * 64]
            for arg in ("packages", "signed", "output", "private-key", "public-key", "work", "sdk"):
                argv.extend(["--" + arg, str(root / arg)])
            copyfile = finalizer.shutil.copyfile
            def changed_copy(source, destination):
                result = copyfile(source, destination)
                if source == image:
                    Path(destination).write_bytes(b"different bytes after index verification")
                return result
            with patch.object(sys, "argv", argv), \
                 patch.object(finalizer.builder, "build_trust", return_value={"trust": "test"}), \
                 patch.object(finalizer.gates, "verify_runtime_release"), \
                 patch.object(finalizer.builder, "updater_environment", return_value={}), \
                 patch.object(finalizer.verifier, "TARGETS", [("macos", "aarch64")]), \
                 patch.object(finalizer.shutil, "copyfile", side_effect=changed_copy), \
                 patch.object(finalizer.builder, "run", side_effect=AssertionError("changed image reached signer")), \
                 self.assertRaises(ValueError):
                finalizer.main()

    def test_missing_signature_stops_main_before_updater_signing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "packages/macos"
            (folder / "shipping").mkdir(parents=True)
            name = finalizer.gates.PACKAGE_NAMES["macos"]
            archive = folder / "shipping" / name
            archive.write_bytes(b"unsigned archive")
            (folder / "package-digests.json").write_text(json.dumps(dict(
                source_sha="a" * 40, release_set_sha256="b" * 64, mode="sign_candidate", platform="macos",
                architecture="aarch64", packages={"shipping": dict(name=name, sha256=finalizer.verifier.digest(archive),
                                                                     size_bytes=archive.stat().st_size)})))
            argv = ["finalize", "--mode", "sign_candidate", "--source-sha", "a" * 40, "--release-set-sha256", "b" * 64]
            for arg in ("packages", "signed", "output", "private-key", "public-key", "work", "sdk"):
                argv.extend(["--" + arg, str(root / arg)])
            with patch.object(sys, "argv", argv), \
                 patch.object(finalizer.builder, "build_trust", return_value={"trust": "release"}), \
                 patch.object(finalizer.gates, "verify_runtime_release"), \
                 patch.object(finalizer.builder, "updater_environment", return_value={}), \
                 patch.object(finalizer.verifier, "TARGETS", [("macos", "aarch64")]), \
                 patch.object(finalizer.builder, "run", side_effect=AssertionError("unsigned macOS reached signer")), \
                 self.assertRaises(ValueError):
                finalizer.main()
