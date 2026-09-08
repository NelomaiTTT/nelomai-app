#!/usr/bin/env python3
"""Run instrumented broker/process tests against an explicitly isolated real panel/PG.

Prerequisite: recorded panel archive serving loopback with lifespan off, a fresh
migrated runtime016_task12_* PostgreSQL database and only synthetic fixtures.
This producer is local test evidence, never exact packaged candidate approval.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PHASES = ["requested", "cleanup_handed_off", "runtime_stopping", "local_stopped", "server_reconciling", "auth_resuming", "complete"]


def run(argv, *, env=None, expected=0):
    result = subprocess.run([str(value) for value in argv], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    if result.returncode != expected:
        raise RuntimeError(f"{Path(str(argv[0])).name} exited {result.returncode}, expected {expected}: {result.stderr[-2000:]}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-root", type=Path, required=True)
    parser.add_argument("--panel-sha", required=True)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--panel-url", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--source-slot", choices=["latest","stable"], default="latest")
    parser.add_argument("--case-filter", choices=["expiry-clean","lost-reconcile","lost-resume"], help="Run only this scoped regression using the already-built driver; never full matrix coverage")
    args = parser.parse_args()
    os.environ["NELOMAI_TEST_SOURCE_SLOT"] = args.source_slot
    target_slot = "stable" if args.source_slot == "latest" else "latest"
    panel = urlsplit(args.panel_url)
    database = urlsplit(args.database_url)
    if (panel.scheme != "http" or panel.hostname != "127.0.0.1" or panel.username or panel.password
            or database.hostname != "127.0.0.1" or not database.path.startswith("/runtime016_task12_")
            or not re.fullmatch(r"[0-9a-f]{40}", args.panel_sha)):
        raise SystemExit("explicit isolated panel/database identities required")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = {"PATH":"/usr/bin:/bin", "LANG":"C", "LC_ALL":"C", "TZ":"UTC", "PYTHONPATH":str(args.panel_root), "DATABASE_URL":args.database_url, "SECRET_KEY":"synthetic-task12-isolated-only"}
    binary = ROOT / "target/debug/examples/real-panel-acceptance"
    if args.case_filter is None:
        run(["cargo", "build", "--locked", "--offline", "-p", "nelomai-client-container", "--example", "real-panel-acceptance"])
    elif not binary.is_file():
        raise SystemExit("scoped regression requires an already-built driver")
    interposer = args.work / "phase-exit.dylib"
    if args.case_filter is None:
        run(["/usr/bin/cc", "-dynamiclib", "-Wall", "-Wextra", "-Werror", ROOT / "scripts/tests/runtime_phase_exit.c", "-o", interposer])
    records = []
    fixture = [sys.executable, ROOT / "scripts/tests/real_panel_fixture.py"]
    def observe(login):
        return json.loads(run([*fixture, "view", login], env=env))
    def prepare(name):
        login = f"task12_{args.work.name}_{name}".lower()
        work = args.work / name
        run([*fixture, "seed", login], env=env)
        run([binary, "login", args.panel_url, work, login])
        return login, work
    def drive(work, login, url=None):
        deadline = time.monotonic()+30
        while True:
            result = json.loads(run([binary, "recover", url or args.panel_url, work, login]))
            if result["phase"] == "complete" or "Pending" not in result["progress"]:
                return result
            assert time.monotonic() < deadline, "real recovery remained pending"
            time.sleep(1)
    def assert_applied(login, result, session_rows=1):
        observed = observe(login)
        assert result["phase"] == "complete" and not result["barrier"]
        assert result["confirmed_identity"]["slot"] == target_slot
        assert result["confirmed_identity"]["session_generation"] == 2
        assert observed["devices"] == observed["active_sessions"] == 1 and observed["sessions"] == session_rows
        assert observed["device_generations"] == [2]
        transitions = observed["transitions"]
        assert len(transitions) == 1 and transitions[0]["state"] == "applied" and not transitions[0]["barrier"]
        assert transitions[0]["operation_id"] == result["operation_id"]
        assert transitions[0]["source_generation"] == 1 and transitions[0]["result_generation"] == 2
        return observed
    for index, phase in enumerate(PHASES if args.case_filter is None else []):
        login = f"task12_phase_{args.work.name}_{index}"
        work = args.work / phase
        fixture = [sys.executable, ROOT / "scripts/tests/real_panel_fixture.py"]
        run([*fixture, "seed", login], env=env)
        run([binary, "login", args.panel_url, work, login])
        fault_env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(interposer), NELOMAI_TEST_EXIT_PHASE=phase)
        if phase == "complete":
            prepared = json.loads(run([binary, "switch", args.panel_url, work, login]))
            assert prepared["phase"] == "auth_resuming" and prepared["barrier"]
            assert observe(login)["device_generations"] == [1]
            run([binary, "recover", args.panel_url, work, login], env=fault_env, expected=91)
        else:
            run([binary, "switch", args.panel_url, work, login], env=fault_env, expected=91)
        journal_path = work / "common/runtime-switch-v1.json"
        before = json.loads(journal_path.read_text())
        assert before["phase"] == phase, "requested fault hook did not reach its phase"
        # A real process exit must release its external child before restart.
        deadline = time.monotonic()+5
        with (work / "native-effect.lock").open("a") as lock:
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("source native effect survived broker exit")
                    time.sleep(.01)
        observed_before = json.loads(run([*fixture, "view", login], env=env))
        result = json.loads(run([binary, "recover", args.panel_url, work, login]))
        assert result["phase"] == "complete" and not result["barrier"]
        assert result["operation_id"] == before["operation_id"]
        expected_slot = target_slot
        assert result["target"]["runtime_slot"] == expected_slot
        assert result["confirmed_identity"]["slot"] == expected_slot
        assert result["confirmed_identity"]["session_generation"] == 2
        observed = json.loads(run([*fixture, "view", login], env=env))
        assert observed["devices"] == 1 and observed["sessions"] == observed["active_sessions"] == 1
        assert observed["device_generations"] == [2] and not observed["leases"] and not observed["jobs"]
        applied = [row for row in observed["transitions"] if row["state"] == "applied"]
        assert len(applied) == 1 and applied[0]["source_generation"] == 1 and applied[0]["result_generation"] == 2 and not applied[0]["barrier"]
        assert len(observed["transitions"]) == 1 and applied[0]["operation_id"] == before["operation_id"]
        records.append({"phase":phase,"before":observed_before,"after":observed,"final_slot":expected_slot,"child_exit":91,"authenticated_bootstrap":True})
        print(f"PASS real panel/process phase {phase}: {expected_slot}, generation 2", flush=True)
    delayed = None
    if args.case_filter is None:
        login, work = prepare("delayed")
        run([*fixture, "lease", login], env=env)
        pending = json.loads(run([binary,"switch",args.panel_url,work,login]))
        assert pending["barrier"] and pending["phase"] == "server_reconciling"
        run([*fixture,"agent-fail",login],env=env)
        before = observe(login)
        assert before["device_generations"] == [1]
        assert before["transitions"][0]["state"] == "cleaning" and before["transitions"][0]["barrier"]
        assert [lease["status"] for lease in before["leases"]] == ["connected"]
        assert [job["status"] for job in before["jobs"]] == ["pending"]
        pending = json.loads(run([binary,"recover",args.panel_url,work,login]))
        assert pending["barrier"] and pending["confirmed_identity"] is None
        run([*fixture,"agent-ack",login],env=env)
        result = drive(work,login)
        after = assert_applied(login,result)
        assert [lease["status"] for lease in after["leases"]] == ["released"]
        assert [job["status"] for job in after["jobs"]] == ["completed"]
        delayed = {"before_ack":before,"after_ack":after,"authenticated_bootstrap":True}
        print("PASS real delayed cleanup: denied ACK preserves barrier; worker ACK releases lease/job",flush=True)
    faults = []
    expiries = []
    for delayed_cleanup in [False,True]:
        if args.case_filter is not None and (args.case_filter != "expiry-clean" or delayed_cleanup):
            continue
        login, work = prepare("expiry_delayed" if delayed_cleanup else "expiry_clean")
        before = observe(login)
        pre_restart = None
        if delayed_cleanup:
            run([*fixture,"lease",login],env=env)
            pending = json.loads(run([binary,"switch",args.panel_url,work,login]))
            assert pending["phase"] == "server_reconciling" and pending["barrier"]
        run([*fixture,"expire-access",login],env=env)
        if delayed_cleanup:
            run([*fixture,"agent-ack",login],env=env)
            result = drive(work,login)
        else:
            pending = json.loads(run([binary,"switch",args.panel_url,work,login]))
            assert pending["phase"] == "auth_resuming" and pending["barrier"] and "Pending" in pending["progress"]
            pre_restart = observe(login)
            assert pre_restart["device_generations"] == [1]
            assert pre_restart["transitions"][0]["state"] == "clean" and pre_restart["transitions"][0]["barrier"]
            assert pre_restart["transitions"][0]["resume_operation_id"] is None
            result = drive(work,login)
        after = assert_applied(login,result,session_rows=2)
        assert before["device_ids"] == after["device_ids"]
        assert {row["family"] for row in after["session_identities"]} == {before["session_identities"][0]["family"]}
        assert [row for row in after["session_identities"] if row["id"] == before["session_identities"][0]["id"]][0]["revoked"]
        expiries.append({"delayed_cleanup":delayed_cleanup,"before":before,"pre_restart":pre_restart,"after":after})
        print(f"PASS real expired access with valid refresh (delayed={delayed_cleanup}): same family/device; rotated session",flush=True)
    for endpoint in ["reconcile","resume"]:
        if args.case_filter is not None and args.case_filter != "lost-"+endpoint:
            continue
        login, work = prepare("drop_"+endpoint)
        marker = args.work / (endpoint+"-dropped.json")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1",0))
            port = reservation.getsockname()[1]
        path = "/api/client/v1/connections/runtime-switch/reconcile" if endpoint == "reconcile" else "/api/client/v1/auth/runtime/resume"
        proxy = subprocess.Popen([sys.executable,str(ROOT/"scripts/tests/real_panel_proxy.py"),"--panel-url",args.panel_url,"--port",str(port),"--drop-path",path,"--marker",str(marker)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.1): break
                except OSError:
                    assert proxy.poll() is None and time.monotonic()<deadline
                    time.sleep(.01)
            url = f"http://127.0.0.1:{port}"
            pending = json.loads(run([binary,"switch",url,work,login]))
            assert pending["barrier"]
            pre_restart = None
            if endpoint == "resume":
                assert pending["phase"] == "auth_resuming" and "Pending" in pending["progress"]
                assert not marker.exists(), "old process must not dispatch resume"
                pre_restart = observe(login)
                assert pre_restart["device_generations"] == [1]
                assert pre_restart["transitions"][0]["resume_operation_id"] is None
                run([binary,"recover",url,work,login],expected=1)
            assert marker.exists()
            fault = json.loads(marker.read_text())
            assert fault["status"] == 200 and fault["response_dropped"]
            before = observe(login)
            assert before["device_generations"] == ([2] if endpoint == "resume" else [1])
            result = drive(work,login,url)
            after = assert_applied(login,result)
            assert before["device_ids"] == after["device_ids"]
            assert before["session_identities"] == after["session_identities"]
            if endpoint == "resume":
                assert before["device_ids"] == pre_restart["device_ids"]
                assert before["session_identities"] == pre_restart["session_identities"]
                assert before["transitions"][0]["state"] == "applied"
                assert before["transitions"][0]["operation_id"] == pending["operation_id"]
                assert before["transitions"][0]["resume_operation_id"] is not None
                assert before["transitions"][0]["resume_operation_id"] == after["transitions"][0]["resume_operation_id"]
            faults.append({"endpoint":endpoint,"fault":fault,"pre_restart":pre_restart,"before_replay":before,"after_replay":after})
            print(f"PASS real postcommit lost {endpoint}: persisted replay, one generation advance",flush=True)
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)
    logout_cases = []
    invalid_refresh_cases = []
    for delayed_cleanup in [False,True]:
        if args.case_filter is not None:
            continue
        login, work = prepare(f"invalid_refresh_{delayed_cleanup}")
        if delayed_cleanup:
            run([*fixture,"lease",login],env=env)
            pending = json.loads(run([binary,"switch",args.panel_url,work,login]))
            assert pending["phase"] == "server_reconciling" and pending["barrier"]
        else:
            fault_env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(interposer), NELOMAI_TEST_EXIT_PHASE="server_reconciling")
            run([binary,"switch",args.panel_url,work,login],env=fault_env,expected=91)
        before = observe(login)
        run([*fixture,"expire-refresh",login],env=env)
        if delayed_cleanup:
            time.sleep(1)  # Honor the real first persisted retry deadline.
        run([binary,"recover",args.panel_url,work,login],expected=1)
        result = json.loads(run([binary,"assert-reauth-required",args.panel_url,work,login]))
        after = observe(login)
        assert after["device_ids"] == before["device_ids"] and after["device_generations"] == [1]
        assert after["sessions"] == 1 and after["active_sessions"] == 0
        assert not (work/"admitted-generation").exists()
        journal = json.loads((work/"common/runtime-switch-v1.json").read_text())
        assert journal["phase"] == "server_reconciling"
        if delayed_cleanup:
            assert after["jobs"][0]["status"] == "pending" and after["leases"][0]["status"] == "connected"
            assert after["transitions"][0]["barrier"]
        invalid_refresh_cases.append({"delayed_cleanup":delayed_cleanup,"before":before,"after":after,"result":result})
        print(f"PASS real invalid refresh: controlled recovery, no admission (delayed={delayed_cleanup})",flush=True)
    for issuance in ["refresh","resume"]:
      if args.case_filter is not None:
        continue
      for delayed_cleanup in [False,True]:
        login, work = prepare(f"logout_{issuance}_{delayed_cleanup}")
        before = observe(login)
        if delayed_cleanup:
            run([*fixture,"lease",login],env=env)
        if issuance == "resume":
            result = json.loads(run([binary,"reconcile",args.panel_url,work,login]))
            if delayed_cleanup:
                assert result["state"] == "Retry"
                run([*fixture,"agent-fail",login],env=env)
                run([*fixture,"agent-ack",login],env=env)
                result = json.loads(run([binary,"reconcile",args.panel_url,work,login]))
            assert result["state"] == "Clean"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1",0))
            port = reservation.getsockname()[1]
        path = "/api/client/v1/auth/refresh" if issuance == "refresh" else "/api/client/v1/auth/runtime/resume"
        proxy = subprocess.Popen([sys.executable,str(ROOT/"scripts/tests/real_panel_proxy.py"),"--panel-url",args.panel_url,"--port",str(port),"--drop-path",path,"--marker",str(work/"response-held"),"--hold","--release",str(work/"release-response"),"--drop-logout-marker",str(work/"logout-dropped")],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.1): break
                except OSError:
                    assert proxy.poll() is None and time.monotonic()<deadline
                    time.sleep(.01)
            url = f"http://127.0.0.1:{port}"
            run([binary,"race-"+issuance,url,work,login])
            assert json.loads((work/"response-held").read_text())["status"] == 200
            assert json.loads((work/"logout-dropped").read_text())["status"] == 200
            revoked = observe(login)
            assert revoked["active_sessions"] == 0 and revoked["device_ids"] == before["device_ids"]
            assert all(row["revoked"] and row["family"] == before["session_identities"][0]["family"] for row in revoked["session_identities"])
            if delayed_cleanup and issuance == "refresh":
                assert revoked["transitions"][0]["barrier"] and revoked["jobs"][0]["status"] == "pending"
                run([*fixture,"agent-fail",login],env=env)
                assert observe(login)["leases"][0]["status"] == "connected"
                run([*fixture,"agent-ack",login],env=env)
            (work/"require-new-lease").write_text("synthetic fixture only")
            fresh = subprocess.Popen([str(binary),"logout-replay-new-login",url,str(work),login],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline = time.monotonic()+10
            while not (work/"new-family-ready").exists():
                assert fresh.poll() is None and time.monotonic()<deadline, "fresh family did not reach lease fixture boundary"
                time.sleep(.01)
            new_lease = json.loads(run([*fixture,"lease",login],env=env))["lease_id"]
            new_before_replay = observe(login)
            (work/"new-lease-ready").write_text("fixture ready")
            output, error = fresh.communicate(timeout=15)
            assert fresh.returncode == 0, error[-1500:]
            after = observe(login)
            (work/"new-family-replay-observations.json").write_text(json.dumps({"before":new_before_replay,"after":after},indent=2))
            assert after == new_before_replay, "old logout replay changed new family or its lease/cleanup ownership"
            assert after["devices"] == after["active_sessions"] == 1
            assert [lease["status"] for lease in after["leases"] if lease["id"] == new_lease] == ["connected"]
            assert all(job["lease_id"] != new_lease for job in after["jobs"])
            active = [row for row in after["session_identities"] if not row["revoked"]]
            assert active[0]["family"] != before["session_identities"][0]["family"]
            logout_cases.append({"issuance":issuance,"delayed_cleanup":delayed_cleanup,"before":before,"revoked":revoked,"after_new_family_old_replay":after,"result":json.loads(output)})
            print(f"PASS real held {issuance}/lost logout/new-family lease replay (delayed={delayed_cleanup})",flush=True)
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)
    source_files = [ROOT/"scripts/run-real-panel-acceptance.py", ROOT/"scripts/tests/real_panel_fixture.py", ROOT/"scripts/tests/real_panel_proxy.py",ROOT/"scripts/tests/runtime_phase_exit.c",ROOT/"crates/client-container/examples/real-panel-acceptance.rs"]
    report = {"scope":"instrumented local real-broker/panel/PostgreSQL process matrix; NOT candidate approval", "panel_archive_claim":args.panel_sha,"source_head":run(["git","rev-parse","HEAD"]).strip(),"tracked_diff_sha256":hashlib.sha256(subprocess.check_output(["git","diff","--binary"],cwd=ROOT)).hexdigest(),"driver_sha256":{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files},"phases":records,"delayed":delayed,"postcommit_faults":faults,"expired_access":expiries}
    report["logout_races"] = logout_cases
    report["invalid_refresh"] = invalid_refresh_cases
    report["source_slot"] = args.source_slot
    report["case_filter"] = args.case_filter
    report["coverage"] = "scoped regression only" if args.case_filter else "implemented local matrix only"
    (args.work / "results.json").write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
