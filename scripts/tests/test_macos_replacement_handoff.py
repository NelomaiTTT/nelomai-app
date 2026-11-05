"""Real AppKit owner detection in private apps; no product, root or VPN."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''
#import <Cocoa/Cocoa.h>
#include <unistd.h>
@interface Delegate : NSObject <NSApplicationDelegate>
@end
@implementation Delegate
- (void)applicationDidFinishLaunching:(NSNotification *)n {
    NSString *root = [[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent];
    [@"active" writeToFile:[root stringByAppendingPathComponent:@"engine-active"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[NSString stringWithFormat:@"%d",getpid()] writeToFile:[root stringByAppendingPathComponent:@"pid"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
- (void)applicationWillTerminate:(NSNotification *)n {
    NSString *root = [[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent];
    [@"requested" writeToFile:[root stringByAppendingPathComponent:@"quit-requested"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
@end
int main(void) { @autoreleasepool {
    [NSApplication sharedApplication]; Delegate *d=[Delegate new]; NSApp.delegate=d; [NSApp run];
} return 0; }
'''

@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("NELOMAI_NATIVE_MACOS_UI_TESTS") == "1", "native macOS desktop opt-in")
class ReplacementHandoffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "--locked", "--offline", "-p", "nelomai-app", "--example", "macos_launch_handoff"], cwd=ROOT, check=True, timeout=600)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT))
        cls.driver = Path(metadata["target_directory"]) / "debug/examples/macos_launch_handoff"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nelomai replace ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "fixture.m"
        self.source.write_text(PROBE)
        self.executables = set()
        self.addCleanup(self.stop_fixtures)

    def stop_fixtures(self):
        # A slow LaunchServices start can exist before the ready file. Select
        # only exact private fixture paths, including this partial-start case.
        rows = subprocess.check_output(["ps", "-axo", "pid=,comm="], text=True)
        for row in rows.splitlines():
            fields = row.strip().split(None, 1)
            if len(fields) == 2 and fields[1] in self.executables:
                try:
                    os.kill(int(fields[0]), 15)
                except ProcessLookupError:
                    pass

    def launch(self, name):
        directory = self.root / name
        bundle = directory / "Nelomai.app"
        executable = bundle / "Contents/MacOS/nelomai-app"
        executable.parent.mkdir(parents=True)
        info = {"CFBundleIdentifier":"local.nelomai.replacement."+uuid.uuid4().hex, "CFBundleExecutable":"nelomai-app", "CFBundlePackageType":"APPL", "LSUIElement":True}
        (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        subprocess.run(["clang", "-fobjc-arc", "-framework", "Cocoa", str(self.source), "-o", str(executable)], check=True)
        self.executables.add(str(executable))
        subprocess.run(["open", "-a", str(bundle)], check=True)
        deadline = time.monotonic()+20
        while not (directory / "pid").exists() and time.monotonic()<deadline:
            time.sleep(.05)
        self.assertTrue((directory / "pid").exists())
        pid = int((directory / "pid").read_text())
        self.assertGreater(pid, 0)
        return bundle, directory

    def check_closed(self, bundle):
        return subprocess.run([str(self.driver), "check-closed", str(bundle)], capture_output=True, text=True, timeout=5)

    def test_running_owner_blocks_replacement_without_requesting_quit(self):
        bundle, directory = self.launch("selected")
        for _ in range(2):
            result = self.check_closed(bundle)
            self.assertNotEqual(result.returncode, 0, "must not authorize replacement of an open owner")
            self.assertTrue((directory / "engine-active").exists())
            self.assertFalse((directory / "quit-requested").exists(), "OS Quit bypasses shipped Tauri cleanup")

    def test_closed_target_permits_retry_and_ignores_unrelated_app(self):
        bundle, directory = self.launch("selected")
        _, other = self.launch("unrelated")
        self.assertNotEqual(self.check_closed(bundle).returncode, 0)
        # Model user closure separately, not as a claim about product cleanup.
        pid = int((directory / "pid").read_text())
        os.kill(pid, 15)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.check_closed(bundle)
            if result.returncode == 0:
                break
            time.sleep(.05)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.check_closed(bundle).returncode, 0)
        self.assertTrue((other / "engine-active").exists())
        self.assertFalse((other / "quit-requested").exists())

if __name__ == "__main__":
    unittest.main()
