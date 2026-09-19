import subprocess
import sys
import json
import os
from types import SimpleNamespace
from unittest.mock import patch
from scripts.tests.test_runtime_artifact import ArtifactFixture, SCRIPTS, module


class ReleasePlatformTest(ArtifactFixture):
    def test_build_capture_decodes_utf8_independently_of_windows_locale(self):
        builder = module("build-release-platform")
        metadata = json.dumps({"description": "Сборка"}, ensure_ascii=False)
        command = "import sys; sys.stdout.buffer.write(" + repr(metadata.encode("utf-8")) + ")"
        with patch.object(subprocess, "_text_encoding", return_value="cp1252"):
            result = builder.run(sys.executable, "-c", command, capture=True)
        self.assertEqual(json.loads(result.stdout), {"description": "Сборка"})

    def test_android_fetches_locked_graph_before_offline_input_generation(self):
        builder = module("build-release-platform")
        events = []
        class InputsReached(Exception):
            pass
        def generate(name, *args, **kwargs):
            self.assertEqual(name, "android/generate-build-inputs.py")
            self.assertIn(("cargo", "fetch", "--locked"), events)
            raise InputsReached()
        args = SimpleNamespace(ndk=self.root, go_archive=self.root / "go.zip")
        with patch.object(builder.verifier, "load_script", return_value=SimpleNamespace(
                ndk_compiler=lambda _: self.root / "clang")), \
             patch.object(builder, "run", side_effect=lambda *args, **kwargs: events.append(args)), \
             patch.object(builder, "script", side_effect=generate):
            with self.assertRaises(InputsReached):
                builder.android(args, self.root, {})

    def test_final_recheck_reaches_linux_and_windows_extractors(self):
        consumer = module("verify-release-platform")
        # Native tool substitutes only unpack a marker; the consumer, subprocess
        # wrapper, inventory hashes and output evidence are real. Native byte
        # admission itself has separate real-platform packaging coverage.
        tool = self.root / "7z"
        tool.write_text('#!/bin/sh\nmkdir -p "${3#-o}"\nprintf extracted > "${3#-o}/marker"\n')
        tool.chmod(0o755)
        for platform in ("linux", "windows"):
            with self.subTest(platform=platform):
                directory = self.root / platform
                arguments = ["verify-release-platform", "--platform", platform, "--architecture", "x86_64",
                    "--source-sha", "a" * 40, "--release-set-sha256", "b" * 64,
                    "--public-key", str(self.public), "--signed", str(self.root / "signed"),
                    "--output", str(directory / "evidence.json")]
                for kind in ("candidate", "acceptance"):
                    folder = directory / kind
                    folder.mkdir(parents=True)
                    name = consumer.gates.PACKAGE_NAMES[platform]
                    if kind == "acceptance":
                        name = name.replace("nelomai-", "nelomai-acceptance-", 1)
                    package = folder / name
                    package.write_text('#!/bin/sh\n[ "$1" = --appimage-extract ] || exit 1\nprintf extracted > marker\n')
                    inventory = folder / (kind + "-inventory.json")
                    inventory.write_text(json.dumps(dict(source_sha="a" * 40, release_set_sha256="b" * 64,
                        assets={name: consumer.verifier.digest(package)})))
                    arguments += ["--" + kind, str(folder),
                        "--inventory-sha256" if kind == "candidate" else "--acceptance-inventory-sha256",
                        consumer.verifier.digest(inventory)]
                def check_extracted(extracted, *_):
                    self.assertEqual((extracted / "marker").read_text(), "extracted")
                with patch.object(sys, "argv", arguments), patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}), \
                     patch.object(consumer.container, "stage_signed", return_value={}), \
                     patch.object(consumer.container, "verify_packaged_tree", side_effect=check_extracted):
                    try:
                        consumer.main()
                    except TypeError as error:
                        self.fail(f"{platform} extraction consumer cannot call its subprocess wrapper: {error}")
                evidence = json.loads((directory / "evidence.json").read_bytes())
                self.assertEqual(evidence["native_reextraction"], "verified")
                self.assertEqual(set(evidence["packages"]), {"shipping", "acceptance"})

    def test_native_draft_cli_never_accepts_a_release_private_key(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "build-release-platform.py"),
            "--platform", "linux", "--architecture", "x86_64", "--source-sha", "a" * 40,
            "--mode", "build_only", "--public-key", str(self.public), "--output", str(self.root / "output"),
            "--work", str(self.root / "work"), "--signing-key", str(self.keyfile)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --signing-key", result.stderr)
        self.assertFalse((self.root / "work").exists())

    def test_build_trust_rejects_promotion_and_mismatched_key_before_building(self):
        self.assertTrue((SCRIPTS / "build-release-platform.py").is_file(), "platform build consumer is missing")
        builder = module("build-release-platform")
        self.assertEqual(builder.build_trust("build_only", self.keyfile, self.public)["trust"], "test")
        with self.assertRaisesRegex(ValueError, "forbidden"):
            builder.build_trust("publish_approved_candidate", self.keyfile, self.public)
        self.public.write_bytes(bytes(32))
        with self.assertRaisesRegex(ValueError, "trust"):
            builder.build_trust("build_only", self.keyfile, self.public)
