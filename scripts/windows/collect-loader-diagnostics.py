#!/usr/bin/env python3
"""Best-effort static evidence for a failed Windows library test, never a retry.

Reads PE imports/exports with the installed MSVC dumpbin. It does not load DLLs,
execute the test image, change the registry, or infer Windows loader resolution.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time


def file_version(path):
    if os.name != "nt":
        return None
    try:
        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        version.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        version.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, data):
            return None
        pointer, length = ctypes.c_void_p(), ctypes.c_uint()
        if not version.VerQueryValueW(data, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return None
        words = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))
        return ".".join(str(value) for value in (words[2] >> 16, words[2] & 65535, words[3] >> 16, words[3] & 65535))
    except (OSError, ValueError):
        return None


def collect(deps, output, dumpbin, search_dirs, *, max_images=128, seconds=90):
    output.mkdir(parents=True, exist_ok=True)
    executables = sorted(deps.glob("nelomai_app_lib-*.exe"))
    report = {"test_executables": [str(path) for path in executables],
              "selected_executable": str(executables[0]) if len(executables) == 1 else None,
              "system": f"{platform.system()} {platform.version()} {platform.machine()}", "environment": {key: os.environ.get(key) for key in
                  ("PATH", "SystemRoot", "ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "SOURCE_SHA")},
              "dumpbin": str(dumpbin) if dumpbin else None,
              "search_directories": [str(path) for path in search_dirs], "images": [],
              "limitations": ["Candidate paths are static search evidence, not observed loaded modules; API sets, KnownDLLs, SxS and forwarders require native interpretation."]}
    deadline = time.monotonic() + seconds
    try:
        if len(executables) != 1:
            report["limitations"].append("Expected exactly one test executable; no ambiguous image selected.")
            return
        exe = executables[0]
        if exe.stat().st_size <= 1024 * 1024 * 1024:
            (output / "binary").mkdir(exist_ok=True)
            shutil.copyfile(exe, output / "binary" / exe.name)
        else:
            report["limitations"].append("Test executable exceeds 1 GiB retention budget.")
        if not dumpbin:
            report["limitations"].append("dumpbin unavailable")
        pending, visited = [exe], set()
        while pending and len(visited) < max_images and time.monotonic() < deadline:
            path = pending.pop(0).resolve()
            identity = str(path).casefold()
            if identity in visited:
                continue
            visited.add(identity)
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            entry = {"path": str(path), "size": path.stat().st_size,
                     "sha256": digest,
                     "file_version": file_version(path), "imports": []}
            report["images"].append(entry)
            if not dumpbin:
                continue
            imports = ""
            for mode in ("imports", "exports"):
                try:
                    result = subprocess.run([str(dumpbin), "/" + mode, str(path)], capture_output=True,
                                            text=True, errors="replace", timeout=max(0.1, min(10, deadline - time.monotonic())))
                    text = result.stdout + result.stderr
                    (output / f"image-{len(report['images']) - 1:03}-{mode}.txt").write_text(text[:1024 * 1024])
                    entry[mode + "_exit_code"] = result.returncode
                    if len(text) > 1024 * 1024:
                        report["limitations"].append(f"{path.name} {mode} truncated at 1 MiB")
                    if mode == "imports":
                        imports = text
                except (OSError, subprocess.SubprocessError) as error:
                    entry[mode + "_error"] = str(error)
            for name in dict.fromkeys(re.findall(r"^\s{4}([^\s]+\.dll)\s*$", imports, re.MULTILINE | re.IGNORECASE)):
                candidates = list(dict.fromkeys(directory / name for directory in [deps, *search_dirs]
                                                if (directory / name).is_file()))
                entry["imports"].append({"name": name, "candidate_paths": [str(candidate) for candidate in candidates]})
                # Inspect every candidate, including PATH shadowing, within the common budgets.
                pending.extend(candidates)
        if pending:
            report["limitations"].append("Image count or 90-second deadline reached; evidence is partial.")
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def collect_events(output):
    # Optional native error text, only this test image and recent loader/WER providers.
    command = r"""Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName=@('Application Popup','Application Error','Windows Error Reporting');StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'nelomai_app_lib-[0-9a-f]+\.exe' } | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Depth 3"""
    try:
        result = subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, errors="replace", timeout=5)
        (output / "application-events.json").write_text(result.stdout[:32768])
    except (OSError, subprocess.SubprocessError) as error:
        (output / "application-events-unavailable.txt").write_text(str(error))


def find_dumpbin():
    found = shutil.which("dumpbin")
    if found:
        return found
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root:
            candidates = sorted(Path(root).glob("Microsoft Visual Studio/*/*/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"))
            if candidates:
                return candidates[-1]
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deps", type=Path, default=Path("target/debug/deps"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    system = Path(os.environ.get("SystemRoot", "C:/Windows"))
    directories = [system / "System32", system, Path.cwd(),
                   *(Path(value) for value in os.environ.get("PATH", "").split(os.pathsep) if value)]
    try:
        collect(args.deps.resolve(), args.output, find_dumpbin(), directories)
        if os.name == "nt":
            collect_events(args.output)
    except Exception as error:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "collector-error.txt").write_text(f"{type(error).__name__}: {error}\n")
