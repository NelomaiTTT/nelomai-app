"""Opt-in contract test against the real panel, using only in-memory SQLite.

Run with the panel's Python environment and PYTHONPATH=<panel>:<panel>/tests,
DATABASE_URL=sqlite+pysqlite:///:memory:. No running panel or VPN is used.
"""

from uuid import uuid4

import pytest
from sqlalchemy import select

from test_client_runtime_switch import (
    active_lease,
    authenticated,
    reconcile_request,
    resume_request,
    runtime_db,  # noqa: F401 - real panel's isolated SQLite fixture
    service,
)
from app.client_auth import ClientAuthError
from app.client_operation_journal import OperationSignature, reserve_operation
from app.client_runtime import ClientRuntimeTarget
from app.client_schemas import ClientRuntimeSupersedeRequest
from app.models import (
    AppConnectionLeaseStatus,
    AppConnectionSession,
    AppConnectionSessionState,
    AppRuntimeTransition,
    ClientOperationState,
)


@pytest.mark.parametrize("invalid_source", [False, True])
def test_applied_supersede_rejected_but_fresh_current_reconcile_accepts_old_owned_ids(
    runtime_db, invalid_source
):
    context, pair = authenticated(runtime_db)
    lease = active_lease(runtime_db, context)
    lease.status = AppConnectionLeaseStatus.RELEASED
    session = AppConnectionSession(
        device_id=context.device.id,
        originating_operation_id=str(uuid4()),
        virtual_address_v4="10.77.0.2/32",
        state=AppConnectionSessionState.STOPPED,
        standby_desired=False,
    )
    runtime_db.add(session)
    operation_id = str(uuid4())
    operation = reserve_operation(
        runtime_db,
        OperationSignature(context.device.id, "start", 1, "a" * 64),
        operation_id,
    )
    operation.state = ClientOperationState.TERMINAL
    runtime_db.commit()
    cleanup = dict(
        lease_ids=[lease.id],
        redundant_session_ids=[session.id],
        client_operation_ids=[operation_id],
    )
    switch = service()
    predecessor = reconcile_request(
        context, target_identity=ClientRuntimeTarget("0.3.2", "0.3.2", 1, "latest"),
        **cleanup,
    )
    assert switch.reconcile_runtime_switch(runtime_db, context, predecessor).state == "clean"
    completed = switch.resume_runtime(runtime_db, resume_request(pair, predecessor))
    assert completed.context.runtime_identity.session_generation == 8
    target = ClientRuntimeTarget("0.3.3", "0.3.3", 1, "latest")
    rejected = ClientRuntimeSupersedeRequest(
        refresh_token=pair.refresh_token,
        operation_id=str(uuid4()),
        superseded_reconcile_operation_id=predecessor.operation_id,
        expected_session_generation=8,
        target_identity=target,
    )
    for _ in range(2):
        with pytest.raises(ClientAuthError) as error:
            switch.supersede_runtime(runtime_db, rejected)
        assert error.value.status_code == 409
        assert error.value.code == "runtime_switch_supersede_conflict"
    assert runtime_db.scalar(select(AppRuntimeTransition).where(
        AppRuntimeTransition.operation_id == rejected.operation_id
    )) is None

    successor = reconcile_request(completed.context, target_identity=target, **cleanup)
    assert successor.operation_id not in {predecessor.operation_id, rejected.operation_id}
    if invalid_source:
        successor = successor.model_copy(update={
            "source_identity": predecessor.source_identity,
            "expected_session_generation": predecessor.expected_session_generation,
        })
        with pytest.raises(ClientAuthError) as error:
            switch.reconcile_runtime_switch(runtime_db, completed.context, successor)
        assert error.value.code == "runtime_switch_generation_conflict"
        return
    first = switch.reconcile_runtime_switch(runtime_db, completed.context, successor)
    assert first.state == "clean"
    assert switch.reconcile_runtime_switch(runtime_db, completed.context, successor) == first
    admitted = switch.resume_runtime(runtime_db, resume_request(pair, successor))
    assert admitted.context.runtime_identity.runtime_version == "0.3.3"
    assert admitted.context.runtime_identity.session_generation == 9
