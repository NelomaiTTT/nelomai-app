"""Exercise our handoff with real LaunchServices/ControlCenter, without VPN."""
import json
import os
from pathlib import Path
import plistlib
import shutil
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
@property(strong) NSStatusItem *item;
@end
@implementation Delegate
- (void)applicationDidFinishLaunching:(NSNotification *)n {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    self.item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    self.item.button.title = @"N-test";
    self.item.button.toolTip = @"Nelomai handoff probe";
    [NSTimer scheduledTimerWithTimeInterval:0.2 repeats:YES block:^(NSTimer *t) {
        NSRect frame = [self.item.button.window convertRectToScreen:self.item.button.frame];
        NSDictionary *state = @{ @"pid":@(getpid()), @"x":@(frame.origin.x),
            @"y":@(frame.origin.y), @"policy":@([NSApp activationPolicy]) };
        NSString *path = [[[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"state.json"];
        [[NSJSONSerialization dataWithJSONObject:state options:0 error:nil] writeToFile:path atomically:YES];
    }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 35*NSEC_PER_SEC),dispatch_get_main_queue(),^{[NSApp terminate:nil];});
}
- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag { return flag; }
@end
int main(void) { @autoreleasepool {
    [NSApplication sharedApplication]; Delegate *d=[Delegate new]; NSApp.delegate=d; [NSApp run];
} return 0; }
'''


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("NELOMAI_NATIVE_MACOS_UI_TESTS") == "1",
                     "opt-in: requires logged-in macOS desktop and Accessibility")
class MacosLaunchHandoffTest(unittest.TestCase):
    def test_handoff_registers_status_item_and_reopens_one_background_owner(self):
        self.check_handoff(False)

    def test_restart_releases_old_owner_before_new_status_item(self):
        self.check_handoff(True)

    def check_handoff(self, restart):
        subprocess.run(["cargo", "build", "--locked", "--offline", "-p", "nelomai-app",
                        "--example", "macos_launch_handoff"], cwd=ROOT, check=True, timeout=600)
        metadata = json.loads(subprocess.check_output([
            "cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT))
        driver = Path(metadata["target_directory"]) / "debug/examples/macos_launch_handoff"
        with tempfile.TemporaryDirectory(prefix="nelomai-handoff-") as temporary:
            root = Path(temporary)
            public = root / "Nelomai.app"
            protected = root / "protected/Nelomai.app"
            info = {"CFBundleIdentifier": "local.nelomai.handoff." + uuid.uuid4().hex,
                    "CFBundleName": "Nelomai Handoff Test", "CFBundleExecutable": "nelomai-app",
                    "CFBundlePackageType": "APPL"}
            config = json.loads((ROOT / "src-tauri/bundle.macos.conf.json").read_bytes())
            supplement = config["bundle"].get("macOS", {}).get("infoPlist")
            if supplement:
                info.update(plistlib.loads((ROOT / "src-tauri" / supplement).read_bytes()))
            for bundle in (public, protected):
                (bundle / "Contents/MacOS").mkdir(parents=True)
                (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
            shutil.copy2(driver, public / "Contents/MacOS/nelomai-app")
            source = root / "probe.m"
            source.write_text(PROBE)
            subprocess.run(["clang", "-fobjc-arc", "-framework", "Cocoa", str(source),
                            "-o", str(protected / "Contents/MacOS/nelomai-app")], check=True)
            state_file = root / "protected/state.json"
            pid = None
            try:
                if restart:
                    with subprocess.Popen([str(public / "Contents/MacOS/nelomai-app"), "restart"]) as parent:
                        deadline = time.monotonic() + 5
                        while not (root / "waiting").exists() and time.monotonic() < deadline:
                            time.sleep(0.05)
                        self.assertTrue((root / "waiting").exists())
                        self.assertIsNone(parent.poll(), "restart fixture already exited")
                        self.assertFalse(state_file.exists(), "new owner started before old owner exited")
                        self.assertEqual(parent.wait(timeout=5), 0)
                else:
                    subprocess.run(["open", str(public)], check=True)
                deadline = time.monotonic() + 10
                state = {}
                while time.monotonic() < deadline:
                    if state_file.exists():
                        state = json.loads(state_file.read_bytes())
                        pid = state["pid"]
                        script = f'''tell application "System Events"
tell (first application process whose unix id is {pid})
repeat with b in menu bars
repeat with i in menu bar items of b
if help of i is "Nelomai handoff probe" then return position of i
end repeat
end repeat
end tell
end tell'''
                        result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
                        if result.returncode == 0 and "," in result.stdout:
                            x, y = map(int, result.stdout.strip().split(","))
                            state.update(x=x, y=y)
                            if x >= 0 and 0 <= y < 100:
                                break
                    time.sleep(0.2)
                self.assertGreaterEqual(state.get("x", -1), 0, f"status item not placed: {state}")
                self.assertLess(state["y"], 100, f"status item is off-screen: {state}")
                for _ in range(3):
                    subprocess.run(["open", str(public)], check=True)
                    time.sleep(0.6)
                    state = json.loads(state_file.read_bytes())
                    self.assertEqual(state["pid"], pid, "reopen started a duplicate owner")
                    self.assertEqual(state["policy"], 1, "reopen promoted common into Dock")
            finally:
                if pid is not None:
                    # Only the exact temporary probe we just launched.
                    path = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
                    if path.endswith(str(protected.relative_to(root)) + "/Contents/MacOS/nelomai-app"):
                        os.kill(pid, 15)


if __name__ == "__main__":
    unittest.main()
