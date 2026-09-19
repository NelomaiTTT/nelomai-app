#!/usr/bin/env python3
"""Observe actual WebKit AT-SPI login controls for one exact runtime PID."""
import argparse
import time


def login_visible(names):
    return {"Вход в Nelomai", "Пароль", "Войти"} <= {name.strip() for name in names if name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    args = parser.parse_args()
    if args.pid <= 1:
        raise SystemExit("actual runtime process required")
    import pyatspi
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        for application in pyatspi.Registry.getDesktop(0):
            if application.get_process_id() != args.pid:
                continue
            names, pending, count = [], [application], 0
            while pending and count < 10000:
                node = pending.pop()
                count += 1
                names.append(node.name or "")
                pending.extend(child for child in node if child is not None)
            if login_visible(names):
                print("Observed real runtime WebView login controls for PID", args.pid)
                return
        time.sleep(0.2)
    raise SystemExit("UNRUN: real runtime WebView login controls were not observed")


if __name__ == "__main__":
    main()
