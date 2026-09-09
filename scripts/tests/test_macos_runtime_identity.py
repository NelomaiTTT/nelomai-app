"""Native Dock identity probe, isolated from auth, installation and VPN."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform == "darwin", "requires macOS AppKit")
class MacosRuntimeIdentityTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("NELOMAI_NATIVE_MACOS_UI_TESTS") == "1", "requires macOS desktop")
    def test_dock_icon_survives_three_hide_show_cycles(self):
        subprocess.run(["cargo", "build", "--locked", "--offline", "-p", "nelomai-app",
                        "--example", "macos_runtime_identity", "--features", "desktop-runtime"], cwd=ROOT, check=True)
        metadata = json.loads(subprocess.check_output([
            "cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT))
        source = Path(metadata["target_directory"]) / "debug/examples/macos_runtime_identity"
        with tempfile.TemporaryDirectory(prefix="nelomai-dock-cycle-") as directory:
            bundle = Path(directory) / "Nelomai Dock Probe.app"
            executable = bundle / "Contents/MacOS/Nelomai"
            executable.parent.mkdir(parents=True)
            shutil.copyfile(source, executable)
            executable.chmod(0o755)
            shutil.copyfile(ROOT / "src-tauri/Info.runtime.macos.plist", bundle / "Contents/Info.plist")
            resources = bundle / "Contents/Resources"
            resources.mkdir()
            shutil.copyfile(ROOT / "src-tauri/icons/icon.icns", resources / "icon.icns")
            subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(bundle)],
                           check=True, capture_output=True)
            marker = Path(directory) / "phase"
            with subprocess.Popen([str(executable), "--cycle", str(marker)]) as process:
                try:
                    def wait_phase(expected):
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            if marker.exists() and marker.read_text() == expected:
                                return
                            time.sleep(0.1)
                        self.fail(f"native cycle did not reach {expected}")

                    rectangle = None

                    def icon(settled=True):
                        nonlocal rectangle
                        # Dock publishes temporary off-screen AX frames while
                        # animating insertion/removal. Capture the settled tile.
                        if settled:
                            time.sleep(1.5)
                            rectangle = subprocess.check_output(["osascript", "-e", '''
tell application "System Events" to tell process "Dock"
return {position, size} of (first UI element of list 1 whose name is "Nelomai Dock Probe")
end tell'''], text=True, timeout=5).strip().replace(" ", "")
                        screenshot = Path(directory) / "dock.png"
                        subprocess.run(["/usr/sbin/screencapture", "-x", "-R" + rectangle,
                                        str(screenshot)], check=True, timeout=5)
                        if output := os.environ.get("NELOMAI_NATIVE_UI_ARTIFACT_DIR"):
                            shutil.copy2(screenshot, Path(output) / "dock-cycle.png")
                        # Inspect the actual Dock tile, not NSApplication's
                        # cached icon or NSRunningApplication's bundle icon.
                        return int(subprocess.check_output(["swift", "-e", f'''
import AppKit
let bitmap = NSBitmapImageRep(data:try! Data(contentsOf:URL(fileURLWithPath:{json.dumps(str(screenshot))})))!
var cyan = 0
for y in 0..<bitmap.pixelsHigh {{ for x in 0..<bitmap.pixelsWide {{
 if let c=bitmap.colorAt(x:x,y:y)?.usingColorSpace(.deviceRGB),
    c.redComponent < 0.32 && c.greenComponent > 0.51 && c.blueComponent > 0.63 {{ cyan += 1 }}
}} }}
print(cyan)
'''], timeout=10))

                    wait_phase("ready")
                    self.assertGreater(icon(), 10, "initial Dock tile has no Nelomai cyan VPN mark")
                    for cycle in range(1, 4):
                        marker.with_suffix(".proceed").touch()
                        self.assertGreater(icon(settled=False), 10,
                                           f"Dock lost Nelomai icon during hide {cycle}")
                        wait_phase(str(cycle))
                        self.assertGreater(icon(), 10, f"Dock lost Nelomai icon after cycle {cycle}")
                finally:
                    process.terminate()
                    process.wait(timeout=5)

    def test_packaged_executable_has_product_name_and_icon(self):
        result = subprocess.run([
            "cargo", "build", "--locked", "--offline", "-p", "nelomai-app",
            "--example", "macos_runtime_identity", "--features", "desktop-runtime",
        ], cwd=ROOT, capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = subprocess.run([
            "cargo", "metadata", "--offline", "--no-deps", "--format-version", "1",
        ], cwd=ROOT, capture_output=True, text=True, check=True)
        source = Path(json.loads(metadata.stdout)["target_directory"]) / "debug/examples/macos_runtime_identity"
        with tempfile.TemporaryDirectory(prefix="nelomai-dock-probe-") as directory:
            # The production packager emits this macOS name. Its archive test
            # independently checks that decision and signed byte preservation.
            executable = Path(directory) / "Nelomai"
            shutil.copy2(source, executable)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
