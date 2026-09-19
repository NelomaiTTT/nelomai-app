"""Transport faults only: forward actual panel HTTP; never generate success."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-url", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--drop-path", required=True)
    parser.add_argument("--marker", required=True, type=Path)
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--release", type=Path)
    parser.add_argument("--drop-logout-marker", type=Path)
    args = parser.parse_args()
    panel = urlsplit(args.panel_url)
    if panel.scheme != "http" or panel.hostname != "127.0.0.1" or panel.username or panel.password:
        raise SystemExit("isolated loopback panel required")
    lock = threading.Lock()
    dropped = False
    logout_dropped = False

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def forward(self):
            nonlocal dropped, logout_dropped
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            connection = http.client.HTTPConnection(panel.hostname, panel.port, timeout=30)
            headers = {key: value for key, value in self.headers.items() if key.lower() not in {"connection", "host"}}
            connection.request(self.command, self.path, body, headers)
            response = connection.getresponse()
            payload = response.read()
            connection.close()
            with lock:
                drop = not dropped and self.path == args.drop_path
                if drop:
                    dropped = True
                drop_logout = args.drop_logout_marker and not logout_dropped and self.path == "/api/client/v1/auth/logout-runtime"
                if drop_logout:
                    logout_dropped = True
            if drop_logout:
                args.drop_logout_marker.write_text(json.dumps({"status":response.status,"response_dropped":True}))
                self.close_connection = True
                return
            if drop:
                # Reading the actual response follows the endpoint's commit.
                # Persist only noncredential boundary metadata.
                args.marker.write_text(json.dumps({"path": self.path, "status": response.status, "response_dropped": not args.hold,"response_held":args.hold}))
                if not args.hold:
                    self.close_connection = True
                    return
                deadline = time.monotonic()+30
                while not args.release or not args.release.exists():
                    if time.monotonic() >= deadline:
                        self.close_connection = True
                        return
                    time.sleep(.01)
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"content-length", "connection", "transfer-encoding"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_POST = forward
        do_GET = forward

    ThreadingHTTPServer(("127.0.0.1", args.port), Proxy).serve_forever()


if __name__ == "__main__":
    main()
