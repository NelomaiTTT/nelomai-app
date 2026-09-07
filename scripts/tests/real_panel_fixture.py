"""Synthetic fixture setup and independent PostgreSQL observations, never auth overrides.

Run with scrubbed environment and PYTHONPATH pointing at the archived panel.
"""
import argparse
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4


def main():
    from app.database import SessionLocal, engine
    from app.models import User, UserRole, Server, ServerType, Interface, Peer, AppDevice, AppSession, AppRuntimeTransition, AppConnectionLease, AppClientCleanupJob
    from app.security import get_password_hash
    from sqlalchemy import select
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["seed", "view", "lease", "agent-fail", "agent-ack", "expire-access", "expire-refresh"])
    parser.add_argument("login")
    args = parser.parse_args()
    if engine.url.host != "127.0.0.1" or not engine.url.database.startswith("runtime016_task12_") or not args.login.startswith("task12_"):
        raise SystemExit("isolated Task12 fixture database required")
    with SessionLocal() as db:
        if args.action == "seed":
            user = User(login=args.login, password_hash=get_password_hash("synthetic-task12-password"), display_name="Task12 isolated", role=UserRole.VIP, expires_at=datetime.now(UTC)+timedelta(days=2))
            server = Server(name=args.login, server_type=ServerType.TIC, host="192.0.2.1")
            interface = Interface(name=args.login, user=user, tic_server=server, listen_port=24012, address_v4="10.252.12.1/24", peer_limit=1)
            interface.peers = [Peer(slot=1)]
            db.add_all([user, server, interface])
            db.commit()
            print(json.dumps({"seeded": args.login}))
            return
        user = db.scalar(select(User).where(User.login == args.login))
        devices = list(db.scalars(select(AppDevice).where(AppDevice.user_id == user.id).order_by(AppDevice.id)))
        ids = [device.id for device in devices]
        sessions = list(db.scalars(select(AppSession).where(AppSession.device_id.in_(ids)).order_by(AppSession.id)))
        if args.action == "lease":
            from app.models import AppPool, AppPoolPeer, AppPoolStatus, AppPoolPeerStatus, AppLayer, RouteMode, AppConnectionLeaseStatus
            assert len(devices) == 1
            server = Server(name="task12-pool-"+str(uuid4()), server_type=ServerType.STRAY, host="192.0.2.1")
            db.add(server)
            db.flush()
            pool = AppPool(server_id=server.id, agent_pool_id=str(uuid4()), interface_name="wg-task12", listen_port=29912, address_v4="10.254.12.1/24", desired_ready_peers=1, low_watermark=0, max_peers_per_interface=2, status=AppPoolStatus.ACTIVE)
            db.add(pool)
            db.flush()
            peer = AppPoolPeer(pool_id=pool.id, agent_peer_id=args.login+"-peer", slot=1, status=AppPoolPeerStatus.LEASED, leased_device_id=ids[0])
            db.add(peer)
            db.flush()
            lease = AppConnectionLease(id=str(uuid4()), start_operation_id=str(uuid4()), device_id=ids[0], pool_peer_id=peer.id, server_id=server.id, layer=AppLayer.STRAY, route_mode=RouteMode.STANDALONE, selection_reason="task12-synthetic", status=AppConnectionLeaseStatus.CONNECTED)
            db.add(lease)
            db.flush()
            peer.lease_id = lease.id
            db.commit()
            print(json.dumps({"lease_id":lease.id}))
            return
        if args.action.startswith("agent-"):
            from app import client_pools
            from app.client_connection_recovery import recover_client_operation
            from app.models import AppPoolPeer
            jobs = list(db.scalars(select(AppClientCleanupJob).where(AppClientCleanupJob.device_id.in_(ids))))
            jobs = [job for job in jobs if job.status.value in {"pending","processing"}]
            assert len(jobs) == 1 and jobs[0].cleanup_reason in {"runtime_switch","revocation"}
            lease = db.get(AppConnectionLease, jobs[0].lease_id)
            peer = db.get(AppPoolPeer, lease.pool_peer_id)
            calls = []
            def external_agent(payload):
                assert payload["action"] == "release_app_peer"
                assert payload["lease"] == {"id":lease.id,"device_id":lease.device_id}
                assert payload["target_state"] == {"status":"ready"}
                calls.append(payload["action"])
                return {"ok":args.action == "agent-ack", "peer":{"agent_peer_id":peer.agent_peer_id,"config_revision":peer.config_revision+1}}
            client_pools._run_agent = external_agent
            outcome = recover_client_operation(db, jobs[0].client_operation_id)
            assert calls == ["release_app_peer"], "actual remote ACK boundary was not reached"
            assert outcome == ("terminal" if args.action == "agent-ack" else "retryable")
            print(json.dumps({"worker_outcome":outcome,"external_agent_calls":calls}))
            return
        if args.action.startswith("expire-"):
            for session in sessions:
                if session.revoked_at is None:
                    session.access_expires_at = datetime.now(UTC)-timedelta(seconds=1)
                    if args.action == "expire-refresh":
                        session.refresh_expires_at = datetime.now(UTC)-timedelta(seconds=1)
            # Simulate time passing for the real captured cleanup proof too;
            # preserve its hash, operation, ownership and all cleanup results.
            for transition in db.scalars(select(AppRuntimeTransition).where(AppRuntimeTransition.device_id.in_(ids))):
                authorities = json.loads(transition.cleanup_authority)
                for authority in authorities:
                    authority["expires_at"] = (datetime.now(UTC)-timedelta(seconds=1)).isoformat()
                transition.cleanup_authority = json.dumps(authorities)
            db.commit()
            print(json.dumps({"expired": args.action}))
            return
        transitions = list(db.scalars(select(AppRuntimeTransition).where(AppRuntimeTransition.device_id.in_(ids)).order_by(AppRuntimeTransition.id)))
        leases = list(db.scalars(select(AppConnectionLease).where(AppConnectionLease.device_id.in_(ids)).order_by(AppConnectionLease.id)))
        jobs = list(db.scalars(select(AppClientCleanupJob).where(AppClientCleanupJob.device_id.in_(ids)).order_by(AppClientCleanupJob.id)))
        print(json.dumps({"devices":len(devices),"device_ids":ids,"session_identities":[{"id":row.id,"family":row.auth_family_id,"device_id":row.device_id,"revoked":row.revoked_at is not None} for row in sessions],"device_generations":[device.session_generation for device in devices],"sessions":len(sessions),"active_sessions":sum(session.revoked_at is None for session in sessions),"transitions":[{"operation_id":row.operation_id,"state":row.state,"barrier":row.admission_blocked,"source_generation":row.source_generation,"result_generation":row.result_generation,"resume_operation_id":row.resume_operation_id} for row in transitions],"leases":[{"id":row.id,"status":row.status.value} for row in leases],"jobs":[{"id":row.id,"status":row.status.value,"lease_id":row.lease_id,"reason":row.cleanup_reason} for row in jobs]}))


if __name__ == "__main__":
    main()
