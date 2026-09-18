"""Unit regression for the runner's identity oracle; not panel integration evidence."""
import importlib.util
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class RetryIdentityTest(unittest.TestCase):
    def test_expiry_rejects_changed_operation_in_first_recovery(self):
        # A recovery must not replace the operation already returned by switch,
        # even if all subsequent recovery and database observations agree with it.
        source = Path(__file__).resolve().parents[1] / "run-real-panel-acceptance.py"
        spec = importlib.util.spec_from_file_location("real_panel_runner", source)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        prior_id = "11111111-1111-4111-8111-111111111111"
        changed_id = "22222222-2222-4222-8222-222222222222"
        pending = {"progress": "pending", "phase": "auth_resuming", "barrier": True,
                   "operation_id": prior_id, "retry_after_seconds": 1, "journal_retry": None}
        before = {"device_ids": [1], "session_identities": [{"id": 1, "family": "family-1", "revoked": False}]}
        pre_restart = {"device_generations": [1], "transitions": [
            {"state": "clean", "barrier": True, "resume_operation_id": None}]}
        after = {"device_ids": [1], "device_generations": [2], "devices": 1,
                 "active_sessions": 1, "sessions": 2, "transitions": [
                     {"state": "applied", "barrier": False, "operation_id": changed_id,
                      "source_generation": 1, "result_generation": 2}],
                 "session_identities": [{"id": 1, "family": "family-1", "revoked": True},
                                        {"id": 2, "family": "family-1", "revoked": False}]}
        complete = {"phase": "complete", "barrier": False, "operation_id": changed_id,
                    "confirmed_identity": {"slot": "stable", "session_generation": 2}}
        for first_phase in ("pending", "complete"):
            with self.subTest(first_recovery=first_phase), tempfile.TemporaryDirectory() as temporary:
                observations = iter([before, pre_restart, after])
                first = dict(pending, operation_id=changed_id) if first_phase == "pending" else complete
                recoveries = iter([first, complete])

                def run(argv, **kwargs):
                    if argv[:2] == ["git", "rev-parse"]:
                        return "0" * 40
                    command = argv[2] if str(argv[1]).endswith("real_panel_fixture.py") else argv[1]
                    if command in ("seed", "login", "expire-access"):
                        return ""
                    if command == "view":
                        return json.dumps(next(observations))
                    if command == "switch":
                        return json.dumps(pending)
                    if command == "recover":
                        return json.dumps(next(recoveries))
                    self.fail(f"unexpected external command: {argv}")

                argv = [str(source), "--panel-root", temporary, "--panel-sha", "0" * 40,
                        "--database-url", "postgresql+psycopg://test@127.0.0.1/runtime016_task12_unit",
                        "--panel-url", "http://127.0.0.1:56590", "--work", str(Path(temporary) / "unit"),
                        "--case-filter", "expiry-clean"]
                with patch.object(runner.sys, "argv", argv), patch.object(runner, "run", run), \
                     patch.object(Path, "is_file", return_value=True), \
                     patch.object(runner.subprocess, "check_output", return_value=b""), \
                     patch.object(runner.time, "sleep"), \
                     patch.dict(runner.os.environ), \
                     redirect_stdout(io.StringIO()), \
                     self.assertRaisesRegex(AssertionError, "recovery operation ID changed"):
                    runner.main()


if __name__ == "__main__":
    unittest.main()
