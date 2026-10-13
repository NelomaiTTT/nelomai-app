//! Selected one-TUN worker ownership. IPC DATA never replaces original handles.
use super::{
    member_carrier_payload::native::WorkerSource,
    member_files::{MemberFiles, PrivateFile, SessionFileIo},
    member_session::{NativeSessionFiles, SessionFiles, WindowsSessionStore},
    member_worker_guard::Guard,
};
use crate::{
    member_dns,
    member_owner::{InterfaceProof, ProcessProof},
    member_pair::{DnsRecord, MemberParameters},
    member_worker_guard::Model,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nelomai_client_tunnel::{
    redundancy::{
        control::PairControl,
        driver::{NativePair, SessionStore},
        evidence::NativeHealthSample,
        network::{
            NetworkJournal, NetworkJournalStore, NetworkOwner, NetworkValue, RouteScope, RouteValue,
        },
        protocol::Member,
        session::{SessionPhase, SessionSnapshot},
        ProbeDatagram, SessionScope, Slot,
    },
    DesktopTunnelOptions,
};
use nelomai_contracts::{
    dispatcher::{EngineIdentity, MutationGuard},
    RedundantHealthProbe,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    io::{self, BufRead, BufReader, Write},
    net::IpAddr,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    rc::Rc,
    sync::{mpsc, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, FILETIME, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::*,
    Networking::WinSock::*,
    System::{JobObjects::*, Threading::*},
};
use zeroize::{Zeroize, Zeroizing};

const FRAME: usize = 65536;
const STOP: Duration = Duration::from_secs(7);
fn failed() -> io::Error {
    io::Error::other("worker_ownership_conflict")
}
fn checked<T>(value: Result<T, impl std::fmt::Debug>) -> io::Result<T> {
    value.map_err(|_| failed())
}
fn slot_index(slot: Slot) -> usize {
    match slot {
        Slot::A => 0,
        Slot::B => 1,
    }
}
fn guid_text(bytes: [u8; 16]) -> String {
    let s = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    )
}
fn identity_value(p: InterfaceProof) -> Value {
    json!({"guid":guid_text(p.guid),"luid":p.luid,"index":p.index})
}
fn same_mapping(p: InterfaceProof) -> io::Result<()> {
    let by_index = super::member_physical::read_identity(p.index)?;
    if by_index.guid != p.guid || by_index.luid != p.luid || by_index.index != p.index {
        return Err(failed());
    }
    let mut row = MIB_IF_ROW2::default();
    row.InterfaceLuid.Value = p.luid;
    if unsafe { GetIfEntry2(&mut row) } != 0
        || row.InterfaceIndex != p.index
        || super::member_carrier_guard::key(row.InterfaceGuid).0 != p.guid
    {
        return Err(failed());
    }
    Ok(())
}
fn absent(requested: [u8; 16], original: Option<InterfaceProof>) -> io::Result<bool> {
    let rows = super::member_carrier_provider::native::table().map_err(|_| failed())?;
    let mut present = false;
    for row in rows {
        if row.identity.guid == requested {
            if original.is_some_and(|p| {
                (row.identity.guid, row.identity.luid, row.identity.index)
                    != (p.guid, p.luid, p.index)
            }) {
                return Err(failed());
            }
            present = true;
        } else if original
            .is_some_and(|p| row.identity.index == p.index || row.identity.luid == p.luid)
        {
            return Err(failed());
        }
    }
    Ok(!present)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressIntent {
    source: [u8; 4],
    attempted: bool,
    acknowledged: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    runtime: EngineIdentity,
    boot: [u8; 16],
    scope: SessionScope,
    requested_guid: [u8; 16],
    process: Option<ProcessProof>,
    interface: Option<InterfaceProof>,
    closing: bool,
    stopped: bool,
    guard: Model,
    guard_pending: Option<crate::member_worker_guard::Plan>,
    network: NetworkJournal,
    dns: Option<DnsRecord>,
    address: Option<AddressIntent>,
}
struct Journal {
    private: MemberFiles,
    owner: Arc<MutationGuard>,
    root: PathBuf,
    current: Record,
    expected: Option<Vec<u8>>,
    // First, cold publication only. These bytes are a cleanup CAS predecessor,
    // never confirmed state or permission to spawn/Start.
    initial_attempt: Option<Vec<u8>>,
    // Unconfirmed cold Closing bytes have only retry/cleanup authority.
    closing_attempt: Option<Vec<u8>>,
}
impl Journal {
    fn save(&mut self, change: impl FnOnce(&mut Record)) -> io::Result<()> {
        if self.initial_attempt.is_some() || self.closing_attempt.is_some() {
            return Err(failed());
        }
        self.owner.verify_at(&self.root.join("engine-owner.lock"))?;
        let mut next = self.current.clone();
        change(&mut next);
        let bytes = serde_json::to_vec(&next).map_err(|_| failed())?;
        if bytes.len() > PrivateFile::Worker.limit() {
            return Err(failed());
        }
        self.private.transaction(|files| {
            files.compare_exchange(PrivateFile::Worker, self.expected.as_deref(), &bytes)?;
            if files.read(PrivateFile::Worker)?.as_deref() != Some(bytes.as_slice()) {
                return Err(failed());
            }
            Ok(())
        })?;
        self.current = next;
        self.expected = Some(bytes);
        Ok(())
    }
    fn verify(&mut self) -> io::Result<()> {
        if self.initial_attempt.is_some() || self.closing_attempt.is_some() {
            return Err(failed());
        }
        self.owner.verify_at(&self.root.join("engine-owner.lock"))?;
        self.private.transaction(|files| {
            if files.read(PrivateFile::Worker)?.as_deref() != self.expected.as_deref() {
                return Err(failed());
            }
            Ok(())
        })
    }
}
type SharedJournal = Rc<RefCell<Journal>>;

struct Rpc {
    send: mpsc::SyncSender<Zeroizing<Vec<u8>>>,
    receive: mpsc::Receiver<io::Result<Value>>,
    next: u64,
    session: u64,
    failed: bool,
}
impl Rpc {
    fn start(child: &mut Child, session: u64) -> io::Result<Self> {
        let mut input = child.stdin.take().ok_or_else(failed)?;
        let output = child.stdout.take().ok_or_else(failed)?;
        let (send, requests) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(1);
        let (responses, receive) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("nelomai-worker-pipe".into())
            .spawn(move || {
                let mut reader = BufReader::new(output);
                while let Ok(bytes) = requests.recv() {
                    let result = (|| {
                        input.write_all(&bytes)?;
                        input.flush()?;
                        let mut reply = Vec::new();
                        // fill_buf bounds allocation BEFORE copying an oversized
                        // child frame; no unbounded read_until on privileged input.
                        loop {
                            let part = reader.fill_buf()?;
                            if part.is_empty() {
                                return Err(failed());
                            }
                            let end = part
                                .iter()
                                .position(|b| *b == b'\n')
                                .map_or(part.len(), |n| n + 1);
                            if reply.len() + end > FRAME {
                                return Err(failed());
                            }
                            reply.extend_from_slice(&part[..end]);
                            reader.consume(end);
                            if reply.last() == Some(&b'\n') {
                                break;
                            }
                        }
                        serde_json::from_slice(&reply).map_err(|_| failed())
                    })();
                    let terminal = result.is_err();
                    if responses.send(result).is_err() || terminal {
                        break;
                    }
                }
            })?;
        Ok(Self {
            send,
            receive,
            next: 0,
            session,
            failed: false,
        })
    }
    fn call(&mut self, mut request: Value, budget: Duration) -> io::Result<Value> {
        #[cfg(test)]
        let stop = request["op"].as_str() == Some("stop");
        if self.failed || budget.is_zero() {
            return Err(failed());
        }
        self.next = self.next.checked_add(1).ok_or_else(failed)?;
        request["id"] = self.next.into();
        request["session"] = self.session.into();
        request["deadline_ms"] = (budget.as_millis().min(u32::MAX as u128) as u32).into();
        let bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| failed())?);
        if let Some(Value::String(secret)) = request.get_mut("configuration") {
            secret.zeroize();
        }
        if bytes.len() + 1 > FRAME {
            return Err(failed());
        }
        let mut bytes = bytes;
        bytes.push(b'\n');
        self.failed = true;
        self.send.try_send(bytes).map_err(|_| failed())?;
        let reply = self.receive.recv_timeout(budget).map_err(|_| failed())??;
        if reply["id"].as_u64() != Some(self.next)
            || reply["session"].as_u64() != Some(self.session)
            || reply["ok"].as_bool().is_none()
        {
            return Err(failed());
        }
        #[cfg(test)]
        if stop
            && super::member_worker_factory_native_tests::STOP_FAULT.with(|fault| {
                if fault.get()
                    == Some(super::member_worker_factory_native_tests::StopFault::StopReply)
                {
                    fault.set(None);
                    true
                } else {
                    false
                }
            })
        {
            return Err(failed());
        }
        // A valid command rejection leaves transport available for scoped Stop.
        self.failed = false;
        if reply["ok"].as_bool() != Some(true) {
            return Err(failed());
        }
        Ok(reply)
    }
}
struct Original {
    source: Rc<WorkerSource>,
    child: RefCell<Option<Child>>,
    job: RefCell<Option<OwnedHandle>>,
    process: Cell<Option<ProcessProof>>,
    interface: Cell<Option<InterfaceProof>>,
    requested: [u8; 16],
    exit_ack: Cell<bool>,
    // Only the original successful native Stop reply supplies this receipt.
    // OS exit and exact absence remain separate cleanup completion evidence.
    close_ack: Cell<bool>,
    start_attempted: Cell<bool>,
    address_ack: Cell<bool>,
}
impl Original {
    fn verify_live(&self) -> io::Result<()> {
        checked(self.source.verify())?;
        let child = self.child.try_borrow().map_err(|_| failed())?;
        let child = child.as_ref().ok_or_else(failed)?;
        if unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } != WAIT_TIMEOUT
            || process_proof(child)? != self.process.get().ok_or_else(failed)?
        {
            return Err(failed());
        }
        let mut in_job = 0;
        let job = self.job.try_borrow().map_err(|_| failed())?;
        if unsafe {
            IsProcessInJob(
                child.as_raw_handle(),
                job.as_ref().ok_or_else(failed)?.as_raw_handle(),
                &mut in_job,
            )
        } == 0
            || in_job == 0
        {
            return Err(failed());
        }
        if let Some(p) = self.interface.get() {
            same_mapping(p)?;
        }
        Ok(())
    }
    fn verify_process_exit(&self) -> io::Result<()> {
        checked(self.source.verify())?;
        if let Some(child) = self.child.try_borrow().map_err(|_| failed())?.as_ref() {
            if !self.exit_ack.get()
                || unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } != WAIT_OBJECT_0
            {
                return Err(failed());
            }
            if let Some(process) = self.process.get() {
                if process_proof(child)? != process {
                    return Err(failed());
                }
                let mut in_job = 0;
                let job = self.job.try_borrow().map_err(|_| failed())?;
                if unsafe {
                    IsProcessInJob(
                        child.as_raw_handle(),
                        job.as_ref().ok_or_else(failed)?.as_raw_handle(),
                        &mut in_job,
                    )
                } == 0
                    || in_job == 0
                {
                    return Err(failed());
                }
            } else if self.start_attempted.get() {
                return Err(failed());
            }
            if let Some(p) = self.interface.get() {
                // Our static filters can pin MIB rundown. This table check
                // rejects identifier reuse before exact filter retirement;
                // final completion still requires positive interface absence.
                absent(self.requested, Some(p))?;
            }
        }
        Ok(())
    }
    fn verify_exit(&self) -> io::Result<()> {
        self.verify_process_exit()?;
        if !absent(self.requested, self.interface.get())? {
            return Err(failed());
        }
        Ok(())
    }
    fn spawn(&self, session: u64) -> io::Result<Rpc> {
        if self.child.borrow().is_some() {
            return Err(failed());
        }
        checked(self.source.verify())?;
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut flags = 0;
        if unsafe { GetHandleInformation(job.as_raw_handle(), &mut flags) } == 0
            || flags & HANDLE_FLAG_INHERIT != 0
        {
            return Err(failed());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as _,
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        *self.job.borrow_mut() = Some(job);
        let child = Command::new(checked(self.source.path())?)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        *self.child.borrow_mut() = Some(child); // retain BEFORE any fallible postflight
        let mut children = self.child.borrow_mut();
        let child = children.as_mut().ok_or_else(failed)?;
        let job = self.job.borrow();
        if unsafe {
            AssignProcessToJobObject(
                job.as_ref().ok_or_else(failed)?.as_raw_handle(),
                child.as_raw_handle(),
            )
        } == 0
        {
            let assignment_error = io::Error::last_os_error();
            // This original child is OUTSIDE the Job; Job close cannot stop it.
            // Retain the same handle even if kill/wait fails, for scoped cleanup.
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            if unsafe { WaitForSingleObject(child.as_raw_handle(), STOP.as_millis() as u32) }
                != WAIT_OBJECT_0
                || child.try_wait()?.is_none()
            {
                return Err(failed());
            }
            self.exit_ack.set(true);
            return Err(assignment_error);
        }
        self.process.set(Some(process_proof(child)?));
        let mut image = vec![0u16; 32768];
        let mut length = image.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(child.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let image = String::from_utf16(&image[..length as usize]).map_err(|_| failed())?;
        if std::fs::canonicalize(image)? != std::fs::canonicalize(checked(self.source.path())?)? {
            return Err(failed());
        }
        // No Start bytes may be sent before the original Job assignment ACK.
        Rpc::start(child, session)
    }
    fn wait_exit(&self, deadline: Instant) -> io::Result<()> {
        let mut children = self.child.borrow_mut();
        let Some(child) = children.as_mut() else {
            drop(children);
            return self.verify_process_exit();
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u32::MAX as u128) as u32;
        if unsafe { WaitForSingleObject(child.as_raw_handle(), remaining) } != WAIT_OBJECT_0
            || child.try_wait()?.is_none()
        {
            return Err(failed());
        }
        self.exit_ack.set(true);
        drop(children);
        self.verify_process_exit()
    }
    fn terminate(&self) -> io::Result<()> {
        let mut children = self.child.borrow_mut();
        if let Some(child) = children.as_mut() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
        }
        Ok(())
    }
}
fn process_proof(child: &Child) -> io::Result<ProcessProof> {
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe {
        GetProcessTimes(
            child.as_raw_handle(),
            &mut created,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let creation_time =
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if creation_time == 0 || child.id() == 0 {
        return Err(failed());
    }
    Ok(ProcessProof {
        pid: child.id(),
        creation_time,
    })
}

pub(crate) struct Completion {
    original: Rc<Original>,
    guard: Option<Rc<RefCell<Guard>>>,
    journal: SharedJournal,
}
impl Completion {
    pub(crate) fn verify(&self, scope: &SessionScope) -> io::Result<()> {
        self.verify_storage(scope)?;
        self.journal.borrow_mut().verify()
    }
    pub(crate) fn verify_storage(&self, scope: &SessionScope) -> io::Result<()> {
        self.original.verify_exit()?;
        if let Some(guard) = &self.guard {
            checked(guard.borrow().verify_terminal())?;
        }
        let journal = self.journal.borrow();
        let record = &journal.current;
        let network = record.network.read_view()?;
        if &record.scope != scope
            || !record.stopped
            || record.guard.interface.is_some()
            || record.guard_pending.is_some()
            || network.current().next().is_some()
            || network.pending().is_some()
            || network.recorded_active().is_some()
            || record.dns.is_some()
            || record.address.is_some()
        {
            return Err(failed());
        }
        Ok(())
    }
    pub(crate) fn bytes(&self) -> io::Result<Vec<u8>> {
        self.journal.borrow().expected.clone().ok_or_else(failed)
    }
}
pub(crate) fn terminal_identity(
    bytes: &[u8],
) -> io::Result<(SessionScope, EngineIdentity, [u8; 16])> {
    let record: Record = serde_json::from_slice(bytes).map_err(|_| failed())?;
    let network = record.network.read_view()?;
    if record.version != 1
        || !record.scope.validate()
        || record.runtime.slot != record.scope.runtime
        || !record.stopped
        || !record.closing
        || record.guard.interface.is_some()
        || record.guard_pending.is_some()
        || record
            .guard
            .snapshot()
            .map_err(|_| failed())?
            .sublayer
            .is_some()
        || network.current().next().is_some()
        || network.pending().is_some()
        || network.recorded_active().is_some()
        || record.dns.is_some()
        || record.address.is_some()
    {
        return Err(failed());
    }
    Ok((record.scope, record.runtime, record.boot))
}
pub(crate) fn verify_terminal_record(bytes: &[u8]) -> io::Result<()> {
    terminal_identity(bytes)?;
    let record: Record = serde_json::from_slice(bytes).map_err(|_| failed())?;
    if !absent(record.requested_guid, None)? {
        return Err(failed());
    }
    Ok(())
}
pub(crate) struct Store {
    session: Rc<RefCell<Option<WindowsSessionStore<NativeSessionFiles>>>>,
    files: Rc<RefCell<NativeSessionFiles>>,
    completed: Rc<RefCell<Option<Rc<Completion>>>>,
    // Only the SAME store's positive terminal Session CAS ACK sets this.
    // Disk DATA can never create it, including after a lost publication ACK.
    terminal_session: Option<SessionSnapshot>,
}
impl SessionStore for Store {
    fn save(&mut self, snapshot: &SessionSnapshot) -> io::Result<()> {
        if snapshot.phase == SessionPhase::Stopped {
            let completion = self.completed.borrow().clone().ok_or_else(failed)?;
            completion.verify(&snapshot.scope)?;
            self.ensure_session(&snapshot.scope)?;
            if let Some(acknowledged) = &self.terminal_session {
                if acknowledged != snapshot {
                    return Err(failed());
                }
            } else {
                self.session
                    .borrow_mut()
                    .as_mut()
                    .ok_or_else(failed)?
                    .save(snapshot)?;
                self.terminal_session = Some(snapshot.clone());
            }
            self.files
                .borrow_mut()
                .complete_worker(&snapshot.scope, &completion, snapshot)
        } else {
            // Failed cold preparation may never have opened the Session store.
            // Cleanup still requires the exact active protected scope; this
            // exception cannot open a store for Starting/Running publication.
            if snapshot.phase == SessionPhase::Stopping {
                self.ensure_session(&snapshot.scope)?;
            }
            self.session
                .borrow_mut()
                .as_mut()
                .ok_or_else(failed)?
                .save(snapshot)
        }
    }
}
impl Store {
    fn ensure_session(&mut self, scope: &SessionScope) -> io::Result<()> {
        if self.session.borrow().is_none() {
            let (store, _) = WindowsSessionStore::open(
                self.files.borrow().clone(),
                scope.clone(),
                super::member_session::RecordKind::Session,
            )?;
            *self.session.borrow_mut() = Some(store);
        }
        Ok(())
    }
}
pub(crate) struct Control {
    scope: SessionScope,
    original: Rc<Original>,
    journal: SharedJournal,
    rpc: Rc<RefCell<Option<Rpc>>>,
    guard: Option<Rc<RefCell<Guard>>>,
    routes: Option<
        NetworkOwner<
            crate::member_routes::MemberRoutes<super::member_routes::NativeRowIo, WorkerIdentity>,
            RouteJournal,
        >,
    >,
    completed: Rc<RefCell<Option<Rc<Completion>>>>,
    members: [Option<(IpAddr, IpAddr)>; 2],
    ready: bool,
    fenced: bool,
    stopped: bool,
    files: Rc<RefCell<NativeSessionFiles>>,
    session: Rc<RefCell<Option<WindowsSessionStore<NativeSessionFiles>>>>,
    parameters: [Option<MemberParameters>; 2],
    probes: [Option<RedundantHealthProbe>; 2],
    generations: [Option<u64>; 2],
    bindings: [Option<crate::member_physical::PhysicalRoute>; 2],
    common_routes: Vec<RouteValue>,
    common_physical: Vec<crate::member_physical::PhysicalRoute>,
    physical: Rc<RefCell<Vec<crate::member_physical::PhysicalRoute>>>,
    options: Option<DesktopTunnelOptions>,
}
struct WorkerIdentity {
    original: Rc<Original>,
    physical: Rc<RefCell<Vec<crate::member_physical::PhysicalRoute>>>,
}
impl crate::member_routes::IdentityCheck for WorkerIdentity {
    fn verify(&mut self, index: u32) -> io::Result<crate::member_routes::NativeProof> {
        self.original.verify_live()?;
        if let Some(p) = self.original.interface.get().filter(|p| p.index == index) {
            return Ok(crate::member_routes::NativeProof {
                index,
                luid: p.luid,
            });
        }
        let path = self
            .physical
            .borrow()
            .iter()
            .find(|p| p.proof.identity.index == index)
            .cloned()
            .ok_or_else(failed)?;
        super::member_physical::verify(
            &path,
            &self
                .original
                .interface
                .get()
                .map(|p| crate::member_physical::InterfaceIdentity {
                    index: p.index,
                    luid: p.luid,
                    guid: p.guid,
                })
                .into_iter()
                .collect::<Vec<_>>(),
        )?;
        Ok(crate::member_routes::NativeProof {
            index,
            luid: path.proof.identity.luid,
        })
    }
}
struct RouteJournal(SharedJournal);
impl NetworkJournalStore for RouteJournal {
    fn save(&mut self, network: &NetworkJournal) -> io::Result<()> {
        self.0
            .borrow_mut()
            .save(|record| record.network = network.clone())
    }
}

pub(crate) fn prepare(
    root: &Path,
    owner: Arc<MutationGuard>,
    files: NativeSessionFiles,
    scope: SessionScope,
) -> io::Result<(Control, Store)> {
    let source = Rc::new(checked(WorkerSource::new(root, owner.clone()))?);
    if source.identity().slot != scope.runtime {
        return Err(failed());
    }
    let mut hash = Sha256::new();
    hash.update(b"nelomai-worker-tun/v1\0");
    hash.update(serde_json::to_vec(&scope).map_err(|_| failed())?);
    let mut requested: [u8; 16] = hash.finalize()[..16].try_into().map_err(|_| failed())?;
    requested[6] = (requested[6] & 15) | 64;
    requested[8] = (requested[8] & 63) | 128;
    if !absent(requested, None)? {
        return Err(failed());
    }
    let record = Record {
        version: 1,
        runtime: source.identity().clone(),
        boot: super::member_boot::boot_id()?,
        scope: scope.clone(),
        requested_guid: requested,
        process: None,
        interface: None,
        closing: false,
        stopped: false,
        guard: Model::empty(scope.clone()),
        guard_pending: None,
        network: NetworkJournal::default(),
        dns: None,
        address: None,
    };
    let mut private = checked(MemberFiles::new())?;
    let expected = private.transaction(|records| records.read(PrivateFile::Worker))?;
    if let Some(old) = &expected {
        let old: Record = serde_json::from_slice(old).map_err(|_| failed())?;
        if !old.stopped || old.scope == scope {
            return Err(failed());
        }
    }
    let journal = Rc::new(RefCell::new(Journal {
        private,
        owner,
        root: root.into(),
        current: record,
        expected,
        initial_attempt: None,
        closing_attempt: None,
    }));
    let original = Rc::new(Original {
        source,
        child: RefCell::new(None),
        job: RefCell::new(None),
        process: Cell::new(None),
        interface: Cell::new(None),
        requested,
        exit_ack: Cell::new(false),
        close_ack: Cell::new(false),
        start_attempted: Cell::new(false),
        address_ack: Cell::new(false),
    });
    let completed = Rc::new(RefCell::new(None));
    let files = Rc::new(RefCell::new(files));
    let session = Rc::new(RefCell::new(None));
    Ok((
        Control {
            scope,
            original,
            journal,
            rpc: Rc::new(RefCell::new(None)),
            guard: None,
            routes: None,
            completed: completed.clone(),
            members: [None, None],
            ready: false,
            fenced: true,
            stopped: false,
            files: files.clone(),
            session: session.clone(),
            parameters: [None, None],
            probes: [None, None],
            generations: [None, None],
            bindings: [None, None],
            common_routes: Vec::new(),
            common_physical: Vec::new(),
            physical: Rc::new(RefCell::new(Vec::new())),
            options: None,
        },
        Store {
            session,
            files,
            completed,
            terminal_session: None,
        },
    ))
}

impl Control {
    fn call(&self, value: Value, budget: Duration) -> io::Result<Value> {
        self.rpc
            .borrow_mut()
            .as_mut()
            .ok_or_else(failed)?
            .call(value, budget)
    }
    fn authorize(&self) -> io::Result<()> {
        self.original.verify_live()?;
        self.journal.borrow_mut().verify()
    }
    fn guard_transition(&mut self, desired: Model, retired: bool) -> io::Result<()> {
        let original = self.original.clone();
        let journal = self.journal.clone();
        checked(
            self.guard
                .as_ref()
                .ok_or_else(failed)?
                .borrow_mut()
                .transition(
                    desired,
                    |current, pending| {
                        journal.borrow_mut().save(|record| {
                            record.guard = current.clone();
                            record.guard_pending = pending.cloned();
                        })
                    },
                    || {
                        if retired {
                            original.verify_process_exit()?;
                        } else {
                            original.verify_live()?;
                        }
                        journal.borrow_mut().verify()
                    },
                ),
        )
    }
    fn attach_device(
        &mut self,
        member: &Member,
        params: MemberParameters,
        path: &crate::member_physical::PhysicalRoute,
    ) -> io::Result<()> {
        let uapi = uapi(member.configuration.expose())?;
        let p = self.original.interface.get().ok_or_else(failed)?;
        super::member_physical::verify(
            path,
            &[crate::member_physical::InterfaceIdentity {
                index: p.index,
                luid: p.luid,
                guid: p.guid,
            }],
        )?;
        self.authorize()?;
        let reply=self.call(json!({"op":"attach","slot":slot_index(member.slot),"configuration":uapi.as_str(),"physical":identity_value(InterfaceProof {index:path.proof.identity.index,luid:path.proof.identity.luid,guid:path.proof.identity.guid})}), Duration::from_secs(10))?;
        let generation = reply["slot_stats"][slot_index(member.slot)]["generation"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(failed)?;
        self.authorize()?;
        super::member_physical::verify(
            path,
            &[crate::member_physical::InterfaceIdentity {
                index: p.index,
                luid: p.luid,
                guid: p.guid,
            }],
        )?;
        self.members[slot_index(member.slot)] = Some((
            IpAddr::V4(params.source),
            IpAddr::V4(member.probe.target_ipv4),
        ));
        self.parameters[slot_index(member.slot)] = Some(params);
        self.probes[slot_index(member.slot)] = Some(member.probe.clone());
        self.generations[slot_index(member.slot)] = Some(generation);
        self.bindings[slot_index(member.slot)] = Some(path.clone());
        Ok(())
    }
    fn create_address(&mut self, source: [u8; 4]) -> io::Result<()> {
        self.authorize()?;
        let p = self.original.interface.get().ok_or_else(failed)?;
        let mut row = address_row(p, source);
        let before = unsafe { GetUnicastIpAddressEntry(&mut row) };
        if before != windows_sys::Win32::Foundation::ERROR_NOT_FOUND {
            return Err(failed());
        }
        self.journal.borrow_mut().save(|r| {
            r.address = Some(AddressIntent {
                source,
                attempted: true,
                acknowledged: false,
            })
        })?;
        let row = address_row(p, source);
        if unsafe { CreateUnicastIpAddressEntry(&row) } != 0 {
            return Err(failed());
        }
        self.original.address_ack.set(true); // SAME original actual Create ACK
        self.journal
            .borrow_mut()
            .save(|r| r.address.as_mut().expect("retained address").acknowledged = true)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.authorize()?;
            let mut actual = address_row(p, source);
            if unsafe { GetUnicastIpAddressEntry(&mut actual) } != 0
                || !address_matches(&actual, p, source)
            {
                return Err(failed());
            }
            if actual.DadState == IpDadStatePreferred {
                break;
            }
            if actual.DadState == IpDadStateDuplicate || Instant::now() >= deadline {
                return Err(failed());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    fn delete_address(&mut self) -> io::Result<()> {
        let source = self
            .journal
            .borrow()
            .current
            .address
            .as_ref()
            .map(|a| a.source);
        if let Some(source) = source {
            if !self.original.address_ack.get()
                || !self
                    .journal
                    .borrow()
                    .current
                    .address
                    .as_ref()
                    .is_some_and(|a| a.acknowledged)
            {
                return Err(failed());
            }
            self.authorize()?;
            let p = self.original.interface.get().ok_or_else(failed)?;
            let mut row = address_row(p, source);
            let code = unsafe { GetUnicastIpAddressEntry(&mut row) };
            if code == 0 {
                if !address_matches(&row, p, source) {
                    return Err(failed());
                }
                if unsafe { DeleteUnicastIpAddressEntry(&row) } != 0 {
                    return Err(failed());
                }
            } else if code != windows_sys::Win32::Foundation::ERROR_NOT_FOUND {
                return Err(failed());
            }
            self.authorize()?;
            if unsafe { GetUnicastIpAddressEntry(&mut address_row(p, source)) }
                != windows_sys::Win32::Foundation::ERROR_NOT_FOUND
            {
                return Err(failed());
            }
            self.journal.borrow_mut().save(|r| r.address = None)?;
        }
        Ok(())
    }
    fn dns(&self) -> io::Result<member_dns::OwnedDns<WorkerDns, super::member_dns::NativeDnsIo>> {
        let p = self.original.interface.get().ok_or_else(failed)?;
        checked(super::member_dns::owned(
            member_dns::OwnedInterface {
                scope: self.scope.clone(),
                guid: p.guid,
                luid: p.luid,
                index: p.index,
            },
            WorkerDns {
                original: self.original.clone(),
                scope: self.scope.clone(),
            },
        ))
    }
    fn set_dns(&mut self, servers: &[IpAddr]) -> io::Result<()> {
        if self.journal.borrow().current.dns.is_some() {
            return Err(failed());
        }
        let mut owner = self.dns()?;
        let baseline = checked(owner.snapshot())?;
        let desired = checked(baseline.with_servers(servers))?;
        self.journal.borrow_mut().save(|r| {
            r.dns = Some(DnsRecord {
                baseline: baseline.clone(),
                current: baseline.clone(),
                pending: Some(desired.clone()),
            })
        })?;
        let actual = checked(owner.compare_exchange(&baseline, &desired))?;
        self.journal.borrow_mut().save(|r| {
            let d = r.dns.as_mut().expect("retained DNS");
            d.current = actual;
            d.pending = None;
        })
    }
    fn restore_dns(&mut self) -> io::Result<()> {
        let saved = self.journal.borrow().current.dns.clone();
        if let Some(saved) = saved {
            let mut owner = self.dns()?;
            let actual = checked(owner.snapshot())?;
            if actual != saved.current && saved.pending.as_ref() != Some(&actual) {
                return Err(failed());
            }
            self.journal.borrow_mut().save(|r| {
                r.dns.as_mut().expect("retained DNS").pending = Some(saved.baseline.clone())
            })?;
            checked(owner.compare_exchange(&actual, &saved.baseline))?;
            self.journal.borrow_mut().save(|r| r.dns = None)?;
        }
        Ok(())
    }
    fn route_values(
        &mut self,
        params: &MemberParameters,
        options: &DesktopTunnelOptions,
    ) -> io::Result<(
        Vec<NetworkValue>,
        Vec<crate::member_physical::PhysicalRoute>,
    )> {
        let p = self.original.interface.get().ok_or_else(failed)?;
        let owned = [crate::member_physical::InterfaceIdentity {
            index: p.index,
            luid: p.luid,
            guid: p.guid,
        }];
        let physical = super::member_physical::capture(&owned)?;
        let mut exclusions = options
            .excluded_ipv4_cidrs
            .iter()
            .map(|s| s.parse::<ipnet::IpNet>().map_err(|_| failed()))
            .collect::<io::Result<Vec<_>>>()?;
        if options.exclude_local_networks {
            exclusions.extend(physical.lan_prefixes());
        }
        let common = exclusions.clone();
        exclusions.push(ipnet::IpNet::from(params.endpoint));
        exclusions.sort();
        exclusions.dedup();
        let mut paths = Vec::new();
        let mut values = Vec::new();
        let mut common_routes = Vec::new();
        let mut common_physical = Vec::new();
        for destination in &exclusions {
            let path = physical
                .resolve_bypass(*destination)
                .map_err(|_| failed())?;
            let desired = RouteValue {
                destination: *destination,
                scope: RouteScope::WindowsInterface(path.proof.identity.index),
                interface: path.proof.identity.index,
                gateway: path.row.route.gateway,
                metric: path.row.route.metric,
            };
            if common.contains(destination) {
                common_physical.push(path.clone());
                common_routes.push(desired.clone());
            }
            // A compatible existing physical row is retained as evidence,
            // never adopted into NetworkOwner or deleted on Stop.
            if path.row.route != desired {
                values.push(NetworkValue::Route(desired));
            }
            paths.push(path);
        }
        for network in ipnet::IpNet::aggregate(&params.allowed) {
            let data = if network.prefix_len() == 0 {
                if network.addr().is_ipv4() {
                    vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()]
                } else {
                    vec!["::/1".parse().unwrap(), "8000::/1".parse().unwrap()]
                }
            } else {
                vec![network]
            };
            for destination in data {
                if !exclusions.iter().any(|e| e.contains(&destination)) {
                    values.push(NetworkValue::Route(RouteValue {
                        destination,
                        scope: RouteScope::WindowsInterface(p.index),
                        interface: p.index,
                        gateway: None,
                        metric: 1,
                    }));
                }
            }
        }
        self.common_routes = common_routes;
        self.common_physical = common_physical;
        Ok((values, paths))
    }
}
fn address_row(p: InterfaceProof, source: [u8; 4]) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = p.index;
    row.InterfaceLuid.Value = p.luid;
    row.Address.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(source),
            },
        },
        sin_zero: [0; 8],
    };
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.OnLinkPrefixLength = 32;
    row.SkipAsSource = false;
    row.DadState = IpDadStateInvalid;
    row
}
fn address_matches(row: &MIB_UNICASTIPADDRESS_ROW, p: InterfaceProof, source: [u8; 4]) -> bool {
    row.InterfaceIndex == p.index
        && unsafe { row.InterfaceLuid.Value } == p.luid
        && unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr } == u32::from_ne_bytes(source)
        && row.OnLinkPrefixLength == 32
        && row.PrefixOrigin == IpPrefixOriginManual
        && row.SuffixOrigin == IpSuffixOriginManual
        && row.ValidLifetime == u32::MAX
        && row.PreferredLifetime == u32::MAX
        && !row.SkipAsSource
}
struct WorkerDns {
    original: Rc<Original>,
    scope: SessionScope,
}
impl member_dns::Identity for WorkerDns {
    fn verify_owned(
        &mut self,
        interface: &member_dns::OwnedInterface,
    ) -> member_dns::Result<member_dns::Ownership> {
        self.original
            .verify_live()
            .map_err(|_| member_dns::DnsError::Ownership)?;
        let p = self
            .original
            .interface
            .get()
            .ok_or(member_dns::DnsError::Ownership)?;
        if interface.scope != self.scope
            || (interface.guid, interface.luid, interface.index) != (p.guid, p.luid, p.index)
        {
            return Err(member_dns::DnsError::Ownership);
        }
        Ok(member_dns::Ownership::NewlyCreated)
    }
}
fn uapi(configuration: &str) -> io::Result<Zeroizing<String>> {
    let canonical = crate::redundancy::slot_configuration(configuration).map_err(|_| failed())?;
    let mut text = Zeroizing::new(String::from("listen_port=0\nreplace_peers=true\n"));
    let mut peer = false;
    for line in canonical.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            peer = line.eq_ignore_ascii_case("[Peer]");
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(failed)?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let field = match (peer, key.as_str()) {
            (false, "address" | "dns" | "table") => continue,
            (false, "privatekey") => "private_key",
            (true, "publickey") => "public_key",
            (true, "presharedkey") => "preshared_key",
            (true, "endpoint") => "endpoint",
            (true, "allowedips") => "allowed_ip",
            (true, "persistentkeepalive") => "persistent_keepalive_interval",
            (
                false,
                "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" | "h1" | "h2" | "h3" | "h4"
                | "i1" | "i2" | "i3" | "i4" | "i5",
            ) => key.as_str(),
            _ => return Err(io::ErrorKind::Unsupported.into()),
        };
        if matches!(field, "private_key" | "public_key" | "preshared_key") {
            let mut bytes = crate::member_pair::decode_peer(value)?;
            text.push_str(field);
            text.push('=');
            for byte in bytes {
                text.push_str(&format!("{byte:02x}"));
            }
            text.push('\n');
            bytes.zeroize();
        } else {
            for value in value.split(',') {
                text.push_str(field);
                text.push('=');
                text.push_str(value.trim());
                text.push('\n');
            }
        }
    }
    if text.len() > FRAME / 2 {
        return Err(failed());
    }
    Ok(text)
}

impl PairControl for Control {
    fn prepare_session(&mut self, scope: &SessionScope) -> io::Result<()> {
        if scope != &self.scope || self.session.borrow().is_some() {
            return Err(failed());
        }
        // SessionControl already retains THIS cold control/store before claim.
        self.files.borrow_mut().claim(scope)?;
        {
            let mut journal = self.journal.borrow_mut();
            if journal.initial_attempt.is_some() || journal.closing_attempt.is_some() {
                return Err(failed());
            }
            journal
                .owner
                .verify_at(&journal.root.join("engine-owner.lock"))?;
            let bytes = serde_json::to_vec(&journal.current).map_err(|_| failed())?;
            if bytes.len() > PrivateFile::Worker.limit() {
                return Err(failed());
            }
            let expected = journal.expected.clone();
            journal.initial_attempt = Some(bytes.clone()); // retain BEFORE IO/Err/unwind
            journal.private.transaction(|files| {
                files.compare_exchange(PrivateFile::Worker, expected.as_deref(), &bytes)?;
                if files.read(PrivateFile::Worker)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(failed());
                }
                Ok(())
            })?;
            journal.expected = Some(bytes);
            journal.initial_attempt = None;
        }
        let (session, previous) = WindowsSessionStore::open(
            self.files.borrow().clone(),
            scope.clone(),
            super::member_session::RecordKind::Session,
        )?;
        if previous.is_some() {
            return Err(failed());
        }
        *self.session.borrow_mut() = Some(session);
        Ok(())
    }
    fn start_primary(
        &mut self,
        scope: &SessionScope,
        member: &Member,
        options: &DesktopTunnelOptions,
    ) -> io::Result<()> {
        if scope != &self.scope
            || self.original.child.borrow().is_some()
            || self.stopped
            || self.journal.borrow().initial_attempt.is_some()
            || self.journal.borrow().closing_attempt.is_some()
            || self.journal.borrow().current.closing
        {
            return Err(failed());
        }
        options.validate().map_err(|_| failed())?;
        let params = MemberParameters::parse(member.configuration.expose())?;
        let _validated = uapi(member.configuration.expose())?;
        let session = u64::from_be_bytes(
            self.original.requested[..8]
                .try_into()
                .map_err(|_| failed())?,
        )
        .max(1);
        *self.rpc.borrow_mut() = Some(self.original.spawn(session)?);
        self.journal
            .borrow_mut()
            .save(|r| r.process = self.original.process.get())?;
        self.original.start_attempted.set(true);
        let reply=self.call(json!({"op":"start","name":format!("NeloWorker-{}",&self.scope.session_id[..8]),"guid":guid_text(self.original.requested),"dll_sha256":self.original.source.dll_sha256()}),Duration::from_secs(30))?;
        let identity = &reply["identity"];
        let p = InterfaceProof {
            guid: self.original.requested,
            luid: identity["luid"]
                .as_u64()
                .filter(|v| *v != 0)
                .ok_or_else(failed)?,
            index: identity["index"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|v| *v != 0)
                .ok_or_else(failed)?,
        };
        if identity["guid"].as_str().map(|s| s.to_ascii_lowercase()) != Some(guid_text(p.guid)) {
            return Err(failed());
        }
        self.original.interface.set(Some(p));
        self.original.verify_live()?;
        self.journal.borrow_mut().save(|r| r.interface = Some(p))?;
        self.guard = Some(Rc::new(RefCell::new(checked(Guard::open(Model::empty(
            self.scope.clone(),
        )))?)));
        let deny = Model {
            version: 1,
            scope: self.scope.clone(),
            interface: Some(p),
            source: Some(IpAddr::V4(params.source)),
            admitted: false,
            weight: None,
        };
        self.guard_transition(deny.clone(), false)?;
        self.create_address(params.source.octets())?;
        if !params.dns.is_empty() {
            self.set_dns(&params.dns)?;
        }
        let (values, physical) = self.route_values(&params, options)?;
        let binding =
            super::member_physical::capture(&[crate::member_physical::InterfaceIdentity {
                index: p.index,
                luid: p.luid,
                guid: p.guid,
            }])?
            .resolve_host(params.endpoint)
            .map_err(|_| failed())?
            .path;
        if physical.len() > crate::member_plan::MAX_ROUTES || !physical.contains(&binding) {
            return Err(failed());
        }
        *self.physical.borrow_mut() = physical;
        self.routes = Some(NetworkOwner::fresh(
            crate::member_routes::MemberRoutes::new(
                super::member_routes::NativeRowIo,
                WorkerIdentity {
                    original: self.original.clone(),
                    physical: self.physical.clone(),
                },
            ),
            RouteJournal(self.journal.clone()),
        ));
        self.routes
            .as_mut()
            .ok_or_else(failed)?
            .select(member.slot, values)?;
        let mut admitted = deny;
        admitted.admitted = true;
        self.guard_transition(admitted, false)?;
        self.attach_device(member, params, &binding)?;
        self.call(
            json!({"op":"switch","slot":slot_index(member.slot)}),
            Duration::from_secs(1),
        )?;
        self.options = Some(options.clone());
        Ok(())
    }
    fn complete_start(&mut self, scope: &SessionScope) -> io::Result<()> {
        if scope != &self.scope {
            return Err(failed());
        }
        self.check_integrity()?;
        self.ready = true;
        self.fenced = false;
        Ok(())
    }
    fn attach(&mut self, scope: &SessionScope, member: &Member) -> io::Result<()> {
        if scope != &self.scope
            || !self.ready
            || self.fenced
            || self.stopped
            || self.members[slot_index(member.slot)].is_some()
        {
            return Err(failed());
        }
        member.validate()?;
        let params = MemberParameters::parse(member.configuration.expose())?;
        let primary = self.parameters[slot_index(member.slot.other())]
            .as_ref()
            .ok_or_else(failed)?;
        // One immutable OS dataplane: B changes only its crypto peer/endpoint.
        if params.source != primary.source
            || params.dns != primary.dns
            || ipnet::IpNet::aggregate(&params.allowed) != ipnet::IpNet::aggregate(&primary.allowed)
        {
            return Err(failed());
        }
        let _validated = uapi(member.configuration.expose())?;
        self.check_integrity()?;
        let p = self.original.interface.get().ok_or_else(failed)?;
        let owned = [crate::member_physical::InterfaceIdentity {
            index: p.index,
            luid: p.luid,
            guid: p.guid,
        }];
        let captured = super::member_physical::capture(&owned)?;
        let mut excluded = Vec::new();
        for route in self.routes.as_ref().ok_or_else(failed)?.excluded_routes() {
            if route.interface == p.index {
                continue;
            }
            let physical = self.physical.borrow();
            let retained = physical
                .iter()
                .find(|path| path.proof.identity.index == route.interface)
                .ok_or_else(failed)?;
            let identity = super::member_physical::read_identity(route.interface)?;
            if identity != retained.proof.identity {
                return Err(failed());
            }
            excluded.push(crate::member_routes::Row::static_route(
                route,
                crate::member_routes::NativeProof {
                    index: identity.index,
                    luid: identity.luid,
                },
            ));
        }
        let path = captured
            .without_owned_rows(&excluded)
            .map_err(|_| failed())?
            .resolve_host(params.endpoint)
            .map_err(|_| failed())?
            .path;
        super::member_physical::verify(&path, &owned)?;
        let (mut values, active) = {
            let journal = self.journal.borrow();
            let network = journal.current.network.read_view()?;
            if network.pending().is_some() || network.stopping() {
                return Err(failed());
            }
            (
                network.current().cloned().collect::<Vec<_>>(),
                network.recorded_active().ok_or_else(failed)?,
            )
        };
        let desired = NetworkValue::Route(RouteValue {
            destination: ipnet::IpNet::from(params.endpoint),
            scope: RouteScope::WindowsInterface(path.proof.identity.index),
            interface: path.proof.identity.index,
            gateway: path.row.route.gateway,
            metric: path.row.route.metric,
        });
        // Preserve A and all common routes. An existing exact physical row is
        // evidence only; do not adopt it into our deletable owned set.
        if desired != NetworkValue::Route(path.row.route.clone()) && !values.contains(&desired) {
            if values.iter().any(|old| old.key() == desired.key()) {
                return Err(failed());
            }
            values.push(desired);
        }
        {
            let mut physical = self.physical.borrow_mut();
            if physical.iter().any(|old| {
                old.proof.identity.index == path.proof.identity.index
                    && old.proof.identity != path.proof.identity
            }) {
                return Err(failed());
            }
            if !physical.contains(&path) {
                if physical.len() >= crate::member_plan::MAX_ROUTES {
                    return Err(failed());
                }
                physical.push(path.clone());
            }
        }
        // Retain every new proof before effects, including ambiguous ACKs; an
        // error is cleanup-only and the caller closes this SAME original pair.
        self.fenced = true;
        super::member_physical::verify(&path, &owned)?;
        self.routes
            .as_mut()
            .ok_or_else(failed)?
            .select(active, values)?;
        self.attach_device(member, params, &path)?;
        self.check_integrity()?;
        self.fenced = false;
        Ok(())
    }
    fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        if scope != &self.scope || !self.ready || self.fenced || self.stopped {
            return Err(failed());
        }
        self.check_integrity()?;
        let active = self
            .routes
            .as_ref()
            .and_then(NetworkOwner::active)
            .ok_or_else(failed)?;
        if active == slot {
            return Err(failed());
        }
        let index = slot_index(slot);
        let Some(params) = &self.parameters[index] else {
            return if self.members[index].is_none()
                && self.generations[index].is_none()
                && self.probes[index].is_none()
                && self.bindings[index].is_none()
            {
                Ok(())
            } else {
                Err(failed())
            };
        };
        let generation = self.generations[index].ok_or_else(failed)?;
        let path = self.bindings[index].as_ref().ok_or_else(failed)?.clone();
        let retired = RouteValue {
            destination: ipnet::IpNet::from(params.endpoint),
            scope: RouteScope::WindowsInterface(path.proof.identity.index),
            interface: path.proof.identity.index,
            gateway: path.row.route.gateway,
            metric: path.row.route.metric,
        };
        let active_params = self.parameters[slot_index(active)]
            .as_ref()
            .ok_or_else(failed)?;
        let active_path = self.bindings[slot_index(active)]
            .as_ref()
            .ok_or_else(failed)?;
        let active_route = RouteValue {
            destination: ipnet::IpNet::from(active_params.endpoint),
            scope: RouteScope::WindowsInterface(active_path.proof.identity.index),
            interface: active_path.proof.identity.index,
            gateway: active_path.row.route.gateway,
            metric: active_path.row.route.metric,
        };
        let shared = retired == active_route || self.common_routes.contains(&retired);
        {
            let journal = self.journal.borrow();
            let network = journal.current.network.read_view()?;
            if network.pending().is_some()
                || network.stopping()
                || network.recorded_active() != Some(active)
            {
                return Err(failed());
            }
        }
        self.fenced = true;
        let reply = self.call(
            json!({"op":"detach","slot":index,"generation":generation}),
            Duration::from_secs(5),
        )?;
        let retired_stats = &reply["slot_stats"][index];
        let active_stats = &reply["slot_stats"][slot_index(active)];
        if retired_stats["closed"].as_bool() != Some(true)
            || retired_stats["generation"]
                .as_u64()
                .is_none_or(|value| value <= generation)
            || active_stats["closed"].as_bool() != Some(false)
            || active_stats["generation"].as_u64() != self.generations[slot_index(active)]
        {
            return Err(failed());
        }
        self.check_integrity()?;
        self.routes
            .as_mut()
            .ok_or_else(failed)?
            .retire_owned_route(active, (!shared).then_some(&retired))?;
        self.check_integrity()?;
        self.members[index] = None;
        self.parameters[index] = None;
        self.probes[index] = None;
        self.generations[index] = None;
        self.bindings[index] = None;
        if !self
            .bindings
            .iter()
            .flatten()
            .any(|current| current == &path)
            && !self.common_physical.contains(&path)
        {
            self.physical
                .borrow_mut()
                .retain(|current| current != &path);
        }
        self.fenced = false;
        Ok(())
    }
    fn rebind_pair(&mut self, _: &SessionScope) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn complete_rebind(&mut self, _: &SessionScope) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn cleanup_pending(&self) -> bool {
        self.fenced && !self.stopped
    }
}
impl NativePair for Control {
    type Socket = WorkerProbe;
    fn check_integrity(&mut self) -> io::Result<()> {
        self.authorize()?;
        checked(
            self.guard
                .as_ref()
                .ok_or_else(failed)?
                .borrow_mut()
                .verify(|| self.original.verify_live()),
        )
    }
    fn sample(&mut self, slot: Slot) -> Option<NativeHealthSample> {
        let index = slot_index(slot);
        if !self.ready || self.fenced || self.members[index].is_none() {
            return None;
        }
        self.check_integrity().ok()?;
        let reply = self
            .call(json!({"op":"sample","slot":index}), Duration::from_secs(1))
            .ok()?;
        self.authorize().ok()?;
        let stats = &reply["slot_stats"][index];
        let closed = stats["closed"].as_bool()?;
        if !closed && stats["generation"].as_u64() != self.generations[index] {
            return None;
        }
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_millis(),
        )
        .ok()?;
        let handshake_fresh = reply["handshakes"][index]
            .as_u64()
            .filter(|value| *value > 0)
            .and_then(|value| now.checked_sub(value))
            .is_some_and(|age| age <= 180_000);
        Some(NativeHealthSample {
            admitted: self.guard.as_ref()?.borrow().current.admitted,
            closed,
            handshake_fresh,
            tx_packets: stats["tx_packets"].as_u64()?,
            rx_data_packets: stats["rx_data_packets"].as_u64()?,
        })
    }
    fn open_probe(&mut self, slot: Slot) -> io::Result<(Self::Socket, String)> {
        if !self.ready || self.fenced || self.stopped {
            return Err(failed());
        }
        self.check_integrity()?;
        let index = slot_index(slot);
        let params = self.parameters[index].as_ref().ok_or_else(failed)?;
        let probe = self.probes[index].as_ref().ok_or_else(failed)?;
        Ok((
            WorkerProbe {
                original: self.original.clone(),
                journal: self.journal.clone(),
                guard: self.guard.as_ref().ok_or_else(failed)?.clone(),
                rpc: self.rpc.clone(),
                slot,
                source: params.source.to_string(),
                target: probe.target_ipv4.to_string(),
                probe: None,
            },
            probe.query_name.clone(),
        ))
    }
    fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> io::Result<()> {
        if scope != &self.scope
            || !self.ready
            || self.fenced
            || self.members[slot_index(slot)].is_none()
        {
            return Err(failed());
        }
        self.check_integrity()?;
        let active = self
            .routes
            .as_ref()
            .and_then(NetworkOwner::active)
            .ok_or_else(failed)?;
        let original = self.original.clone();
        let journal = self.journal.clone();
        let guard = self.guard.as_ref().ok_or_else(failed)?.clone();
        let rpc = self.rpc.clone();
        self.fenced = true;
        self.routes
            .as_mut()
            .ok_or_else(failed)?
            .select_metadata(active, slot, || {
                original.verify_live()?;
                journal.borrow_mut().verify()?;
                checked(guard.borrow_mut().verify(|| original.verify_live()))?;
                rpc.borrow_mut().as_mut().ok_or_else(failed)?.call(
                    json!({"op":"switch","slot":slot_index(slot)}),
                    Duration::from_secs(1),
                )?;
                original.verify_live()?;
                journal.borrow_mut().verify()?;
                checked(guard.borrow_mut().verify(|| original.verify_live()))
            })?;
        self.check_integrity()?;
        self.fenced = false;
        Ok(())
    }
    fn close(&mut self, scope: &SessionScope) -> io::Result<()> {
        if scope != &self.scope {
            return Err(failed());
        }
        if self.stopped {
            return self
                .completed
                .borrow()
                .as_ref()
                .ok_or_else(failed)?
                .verify(scope);
        }
        let deadline = Instant::now() + STOP;
        self.ready = false;
        self.fenced = true;
        let closing_published = self.journal.borrow().initial_attempt.is_some();
        if closing_published {
            // This exception is only the retained first publication, before
            // ANY original Job/Child/Start/interface or network effect existed.
            if self.original.child.borrow().is_some()
                || self.original.job.borrow().is_some()
                || self.original.process.get().is_some()
                || self.original.interface.get().is_some()
                || self.original.start_attempted.get()
                || self.original.address_ack.get()
                || self.rpc.borrow().is_some()
                || self.guard.is_some()
                || self.routes.is_some()
            {
                return Err(failed());
            }
            self.original.verify_process_exit()?;
            let mut journal = self.journal.borrow_mut();
            let record = &journal.current;
            let network = record.network.read_view()?;
            if record.scope != self.scope
                || record.process.is_some()
                || record.interface.is_some()
                || record.closing
                || record.stopped
                || record.guard != Model::empty(self.scope.clone())
                || record.guard_pending.is_some()
                || network.current().next().is_some()
                || network.pending().is_some()
                || network.recorded_active().is_some()
                || record.address.is_some()
                || record.dns.is_some()
            {
                return Err(failed());
            }
            journal
                .owner
                .verify_at(&journal.root.join("engine-owner.lock"))?;
            let attempted = journal.initial_attempt.as_ref().ok_or_else(failed)?.clone();
            if attempted != serde_json::to_vec(record).map_err(|_| failed())? {
                return Err(failed());
            }
            let expected = journal.expected.clone();
            let mut closing = record.clone();
            closing.closing = true;
            let bytes = serde_json::to_vec(&closing).map_err(|_| failed())?;
            if journal
                .closing_attempt
                .as_ref()
                .is_some_and(|attempt| attempt != &bytes)
            {
                return Err(failed());
            }
            let previous_closing = journal.closing_attempt.clone();
            let Journal {
                private,
                closing_attempt,
                ..
            } = &mut *journal;
            private.transaction(|files| {
                let predecessor = files.read(PrivateFile::Worker)?;
                if predecessor != expected
                    && predecessor.as_deref() != Some(attempted.as_slice())
                    && previous_closing
                        .as_ref()
                        .is_none_or(|attempt| predecessor.as_deref() != Some(attempt.as_slice()))
                {
                    return Err(failed());
                }
                // Matching attempted bytes grant only this cleanup CAS. Only
                // its original positive write/readback ACK confirms Closing.
                // Retain exact desired bytes BEFORE the actual CAS Err/unwind.
                *closing_attempt = Some(bytes.clone());
                files.compare_exchange(PrivateFile::Worker, predecessor.as_deref(), &bytes)?;
                if files.read(PrivateFile::Worker)?.as_deref() != Some(bytes.as_slice()) {
                    return Err(failed());
                }
                Ok(())
            })?;
            journal.current = closing;
            journal.expected = Some(bytes);
            journal.initial_attempt = None;
            journal.closing_attempt = None;
        }
        let mut error = None;
        let mut withdrawn = false;
        if !closing_published {
            if let Err(e) = self.journal.borrow_mut().save(|r| r.closing = true) {
                error = Some(e);
            }
        }
        if let Some(guard) = &self.guard {
            let mut deny = guard.borrow().current.clone();
            deny.admitted = false;
            if deny.interface.is_some() {
                #[cfg(test)]
                let interrupted = super::member_worker_factory_native_tests::STOP_FAULT.with(|fault| {
                    if fault.get() == Some(super::member_worker_factory_native_tests::StopFault::GuardWithdrawal) {
                        fault.set(None);
                        true
                    } else {
                        false
                    }
                });
                #[cfg(not(test))]
                let interrupted = false;
                match if interrupted {
                    Err(failed())
                } else {
                    self.guard_transition(deny, false)
                } {
                    Ok(()) => withdrawn = true,
                    Err(e) => error = Some(e),
                }
            }
        }
        if let Some(routes) = &mut self.routes {
            #[cfg(test)]
            let interrupted = super::member_worker_factory_native_tests::STOP_FAULT.with(|fault| {
                if fault.get()
                    == Some(super::member_worker_factory_native_tests::StopFault::RoutesCleanup)
                {
                    fault.set(None);
                    true
                } else {
                    false
                }
            });
            #[cfg(not(test))]
            let interrupted = false;
            if let Err(e) = if interrupted {
                Err(failed())
            } else {
                routes.cleanup()
            } {
                error = Some(e);
            }
        }
        if let Err(e) = self.restore_dns() {
            error = Some(e);
        }
        if let Err(e) = self.delete_address() {
            error = Some(e);
        }
        // Cleanup needs this original live worker/interface. After DATA
        // withdrawal, preserve that prerequisite for the same scoped retry.
        if withdrawn
            && error.is_some()
            && self.original.child.borrow().as_ref().is_some_and(|child| {
                (unsafe { WaitForSingleObject(child.as_raw_handle(), 0) }) == WAIT_TIMEOUT
            })
        {
            return Err(error.take().ok_or_else(failed)?);
        }
        if self.original.child.borrow().is_some() && !self.original.exit_ack.get() {
            if self.rpc.borrow().is_some() {
                match self.call(
                    json!({"op":"stop","await_absence":false}),
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(4)),
                ) {
                    Ok(reply)
                        if reply["closed"].as_bool() == Some(true)
                            && reply["absent"].as_bool() == Some(false) =>
                    {
                        self.original.close_ack.set(true)
                    }
                    _ => {
                        error = Some(failed());
                    }
                }
            } else {
                // No Start bytes were ever sent (e.g. Job assignment Err).
                if let Err(e) = self.original.terminate() {
                    error = Some(e);
                }
                if self.original.start_attempted.get() {
                    error = Some(failed());
                }
            }
            self.rpc.borrow_mut().take();
            if !self.original.close_ack.get() {
                let _ = self.original.terminate();
            }
            if let Err(e) = self.original.wait_exit(deadline) {
                error = Some(e);
            }
        }
        // Static index filters may themselves pin MIB rundown. Original Child
        // exit (not interface absence) authorizes exact owned filter retirement.
        let network_empty = {
            let journal = self.journal.borrow();
            let network = journal.current.network.read_view()?;
            network.current().next().is_none()
                && network.pending().is_none()
                && network.recorded_active().is_none()
        };
        if self.original.verify_process_exit().is_ok()
            && network_empty
            && self.journal.borrow().current.dns.is_none()
            && self.journal.borrow().current.address.is_none()
            && self.guard.is_some()
        {
            if self
                .guard
                .as_ref()
                .unwrap()
                .borrow()
                .current
                .interface
                .is_some()
            {
                if let Err(e) = self.guard_transition(Model::empty(self.scope.clone()), true) {
                    error = Some(e);
                }
            }
            if error.is_none()
                && self
                    .guard
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .verify_terminal()
                    .is_err()
            {
                if let Err(e) = checked(self.guard.as_ref().unwrap().borrow_mut().close()) {
                    error = Some(e);
                }
            }
        }
        loop {
            match self.original.verify_exit() {
                Ok(()) => break,
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(e) = error {
            return Err(e);
        }
        self.journal.borrow_mut().save(|r| {
            r.stopped = true;
            r.guard = Model::empty(r.scope.clone());
            r.guard_pending = None;
        })?;
        let completed = Rc::new(Completion {
            original: self.original.clone(),
            guard: self.guard.clone(),
            journal: self.journal.clone(),
        });
        completed.verify(scope)?;
        *self.completed.borrow_mut() = Some(completed);
        self.stopped = true;
        Ok(())
    }
}

// One real query handle over the original inherited worker pipe. The selected
// member supplies its source, target and name; no caller-defined probe endpoint.
pub(crate) struct WorkerProbe {
    original: Rc<Original>,
    journal: SharedJournal,
    guard: Rc<RefCell<Guard>>,
    rpc: Rc<RefCell<Option<Rpc>>>,
    slot: Slot,
    source: String,
    target: String,
    probe: Option<u64>,
}
impl WorkerProbe {
    fn call(&mut self, request: Value) -> io::Result<Value> {
        self.original.verify_live()?;
        self.journal.borrow_mut().verify()?;
        let reply = self
            .rpc
            .borrow_mut()
            .as_mut()
            .ok_or_else(failed)?
            .call(request, Duration::from_secs(1))?;
        self.original.verify_live()?;
        self.journal.borrow_mut().verify()?;
        Ok(reply)
    }
}
impl ProbeDatagram for WorkerProbe {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        if self.probe.is_some()
            || packet.len() < 12
            || packet.len() > 4096
            || !self.guard.borrow().current.admitted
        {
            return Err(failed());
        }
        checked(
            self.guard
                .borrow_mut()
                .verify(|| self.original.verify_live()),
        )?;
        let reply=self.call(json!({"op":"probe_send","slot":slot_index(self.slot),"source":self.source,"target":self.target,"dns":STANDARD.encode(packet)}))?;
        self.probe = Some(
            reply["probe"]
                .as_u64()
                .filter(|id| *id > 0)
                .ok_or_else(failed)?,
        );
        Ok(packet.len())
    }
    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        let probe = self.probe.ok_or_else(failed)?;
        if !self.guard.borrow().current.admitted {
            return Err(failed());
        }
        let reply = self.call(json!({"op":"probe_poll","probe":probe}))?;
        if reply["probe"].as_u64() != Some(probe) {
            return Err(failed());
        }
        let encoded = match reply.get("dns") {
            None => return Err(io::ErrorKind::WouldBlock.into()),
            Some(Value::String(value)) if value.len() <= 5464 => value,
            _ => return Err(failed()),
        };
        let bytes = STANDARD.decode(encoded).map_err(|_| failed())?;
        if bytes.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if bytes.len() > 4096 || bytes.len() > packet.len() {
            return Err(failed());
        }
        packet[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}
impl Drop for WorkerProbe {
    fn drop(&mut self) {
        if let Some(probe) = self.probe.take() {
            // Cancel a still-owned token on its SAME worker, including failure;
            // no reconnect, replacement process, synthetic ACK or retry socket.
            let _ = self.call(json!({"op":"probe_cancel","probe":probe}));
        }
    }
}
