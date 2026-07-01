use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const FALLBACK_NOTICE: &str =
    "open fd list: showing open file descriptors only, not actual read/write I/O.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoOperation {
    Read = 0,
    Write = 1,
}

impl TryFrom<u8> for IoOperation {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            _ => Err(()),
        }
    }
}

/// Aya 백엔드가 syscall exit 시 user-space로 전달할 수 있는 이벤트 형식이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FileIoEvent {
    pub pid: u32,
    pub tid: u32,
    pub fd: i32,
    pub op: u8,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct ResolvedFileIoEvent {
    pub event: FileIoEvent,
    pub process_start_time: u64,
    pub path: String,
    pub occurred_at: Instant,
}

pub struct FileIoEventSource {
    receiver: Receiver<ResolvedFileIoEvent>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl FileIoEventSource {
    pub fn start() -> Result<Self, String> {
        const EBPF_OBJECT: &[u8] =
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/file_io.bpf.o"));

        if EBPF_OBJECT.is_empty() {
            return Err("eBPF object was not built; install clang with BPF target support".into());
        }

        let mut ebpf = Ebpf::load(EBPF_OBJECT).map_err(|error| {
            format!(
                "failed to load eBPF object: {error}; try running as root or with CAP_BPF/CAP_PERFMON"
            )
        })?;
        attach_syscall_tracepoints(&mut ebpf)?;

        let events = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| "eBPF EVENTS ring buffer is missing".to_string())?;
        let mut ring_buffer = RingBuf::try_from(events)
            .map_err(|error| format!("failed to open eBPF ring buffer: {error}"))?;
        let (sender, receiver) = mpsc::sync_channel(65_536);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let monitor_pid = std::process::id();
        let worker = thread::Builder::new()
            .name("apps-disk-io-ebpf".into())
            .spawn(move || {
                // Programs and their links remain attached while `ebpf` is alive.
                let _ebpf = ebpf;

                while !worker_stop.load(Ordering::Relaxed) {
                    let mut received_event = false;

                    while let Some(item) = ring_buffer.next() {
                        received_event = true;
                        let Some(event) = parse_file_io_event(&item) else {
                            continue;
                        };
                        // Resolving an event reads `/proc`; ignore our own I/O to avoid feedback.
                        if event.pid == monitor_pid {
                            continue;
                        }
                        let resolved = ResolvedFileIoEvent {
                            process_start_time: read_process_start_time(event.pid)
                                .unwrap_or_default(),
                            path: resolve_fd_path(event.pid, event.fd),
                            event,
                            occurred_at: Instant::now(),
                        };

                        match sender.try_send(resolved) {
                            Ok(()) | Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Disconnected(_)) => return,
                        }
                    }

                    if !received_event {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            })
            .map_err(|error| format!("failed to start eBPF event reader: {error}"))?;

        Ok(Self {
            receiver,
            stop,
            worker: Some(worker),
        })
    }

    pub fn try_recv(&self) -> Option<ResolvedFileIoEvent> {
        self.receiver.try_recv().ok()
    }
}

impl Drop for FileIoEventSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn attach_syscall_tracepoints(ebpf: &mut Ebpf) -> Result<(), String> {
    // TODO: Add matching eBPF programs/probes for preadv/pwritev variants,
    // copy_file_range, sendfile, io_uring, and mmap-based I/O.
    for syscall in ["read", "write", "pread64", "pwrite64", "readv", "writev"] {
        attach_tracepoint(
            ebpf,
            &format!("enter_{syscall}"),
            &format!("sys_enter_{syscall}"),
        )?;
        attach_tracepoint(
            ebpf,
            &format!("exit_{syscall}"),
            &format!("sys_exit_{syscall}"),
        )?;
    }
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, program_name: &str, tracepoint: &str) -> Result<(), String> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| format!("eBPF program '{program_name}' is missing"))?
        .try_into()
        .map_err(|error| format!("'{program_name}' is not a tracepoint program: {error}"))?;

    program
        .load()
        .map_err(|error| format!("failed to load '{program_name}': {error}"))?;
    program
        .attach("syscalls", tracepoint)
        .map_err(|error| format!("failed to attach '{tracepoint}': {error}"))?;
    Ok(())
}

fn parse_file_io_event(bytes: &[u8]) -> Option<FileIoEvent> {
    if bytes.len() < mem::size_of::<FileIoEvent>() {
        return None;
    }

    Some(FileIoEvent {
        pid: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
        tid: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
        fd: i32::from_ne_bytes(bytes[8..12].try_into().ok()?),
        op: bytes[12],
        bytes: u64::from_ne_bytes(bytes[16..24].try_into().ok()?),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileIoKey {
    pid: u32,
    process_start_time: u64,
    fd: i32,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIoStats {
    pub pid: u32,
    pub process_start_time: u64,
    pub fd: i32,
    pub path: String,
    pub read_bytes_interval: u64,
    pub write_bytes_interval: u64,
    pub cumulative_read: u64,
    pub cumulative_write: u64,
    pub cumulative_total: u64,
    pub last_io_at: Instant,
}

impl FileIoStats {
    pub fn interval_total(&self) -> u64 {
        self.read_bytes_interval
            .saturating_add(self.write_bytes_interval)
    }

    pub fn operation_label(&self) -> &'static str {
        match (self.cumulative_read > 0, self.cumulative_write > 0) {
            (true, true) => "r,w",
            (true, false) => "r",
            (false, true) => "w",
            (false, false) => "-",
        }
    }
}

/// 이벤트 공급원과 독립적인 파일별 누적기다. 향후 Aya 이벤트를 이 구조에 기록한다.
#[derive(Debug, Default)]
pub struct FileIoAccumulator {
    stats: HashMap<FileIoKey, FileIoStats>,
}

impl FileIoAccumulator {
    pub fn begin_interval(&mut self) {
        for stats in self.stats.values_mut() {
            stats.read_bytes_interval = 0;
            stats.write_bytes_interval = 0;
        }
    }

    pub fn retain_recent(&mut self, now: Instant, retention: Duration) {
        self.stats
            .retain(|_, stats| now.duration_since(stats.last_io_at) < retention);
    }

    pub fn record_event(
        &mut self,
        event: FileIoEvent,
        process_start_time: u64,
        path: String,
        occurred_at: Instant,
    ) {
        if event.bytes == 0 {
            return;
        }

        let Ok(operation) = IoOperation::try_from(event.op) else {
            return;
        };
        let key = FileIoKey {
            pid: event.pid,
            process_start_time,
            fd: event.fd,
            path: path.clone(),
        };
        let stats = self.stats.entry(key).or_insert_with(|| FileIoStats {
            pid: event.pid,
            process_start_time,
            fd: event.fd,
            path,
            read_bytes_interval: 0,
            write_bytes_interval: 0,
            cumulative_read: 0,
            cumulative_write: 0,
            cumulative_total: 0,
            last_io_at: occurred_at,
        });

        match operation {
            IoOperation::Read => {
                stats.read_bytes_interval = stats.read_bytes_interval.saturating_add(event.bytes);
                stats.cumulative_read = stats.cumulative_read.saturating_add(event.bytes);
            }
            IoOperation::Write => {
                stats.write_bytes_interval = stats.write_bytes_interval.saturating_add(event.bytes);
                stats.cumulative_write = stats.cumulative_write.saturating_add(event.bytes);
            }
        }

        stats.cumulative_total = stats.cumulative_read.saturating_add(stats.cumulative_write);
        stats.last_io_at = occurred_at;
    }

    pub fn sorted_for_pid(&self, pid: u32, limit: usize) -> Vec<&FileIoStats> {
        let mut stats: Vec<_> = self
            .stats
            .values()
            .filter(|stats| stats.pid == pid && stats.cumulative_total > 0)
            .collect();

        stats.sort_unstable_by(|left, right| {
            right
                .cumulative_total
                .cmp(&left.cumulative_total)
                .then_with(|| right.last_io_at.cmp(&left.last_io_at))
                .then_with(|| left.fd.cmp(&right.fd))
                .then_with(|| left.path.cmp(&right.path))
        });
        stats.truncate(limit);
        stats
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileCandidate {
    pub fd: i32,
    pub path: String,
}

pub type FallbackDetails = HashMap<u32, Vec<OpenFileCandidate>>;

pub fn collect_fallback_details<I>(pids: I, limit: usize) -> FallbackDetails
where
    I: IntoIterator<Item = u32>,
{
    pids.into_iter()
        .map(|pid| (pid, collect_open_file_candidates(pid, limit)))
        .collect()
}

fn collect_open_file_candidates(pid: u32, limit: usize) -> Vec<OpenFileCandidate> {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    let mut files = Vec::new();

    for entry in entries.flatten() {
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|fd| fd.parse::<i32>().ok())
        else {
            continue;
        };
        files.push(OpenFileCandidate {
            fd,
            path: resolve_fd_path(pid, fd),
        });
    }

    files.sort_unstable_by_key(|file| file.fd);
    files.truncate(limit);
    files
}

pub fn resolve_fd_path(pid: u32, fd: i32) -> String {
    fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("fd:{fd} (unresolved)"))
}

pub fn read_process_start_time(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_process_start_time(&stat)
}

fn parse_process_start_time(stat: &str) -> io::Result<u64> {
    // `comm` may contain spaces and parentheses, so split only after its final `)`.
    let comm_end = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid /proc/<pid>/stat format",
        )
    })?;
    stat[comm_end + 1..]
        .split_whitespace()
        .nth(19) // field 22 (starttime); this slice starts at field 3 (state)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "starttime field is missing"))?
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pid: u32, fd: i32, operation: IoOperation, bytes: u64) -> FileIoEvent {
        FileIoEvent {
            pid,
            tid: pid,
            fd,
            op: operation as u8,
            bytes,
        }
    }

    fn file_stats(read_bytes_interval: u64, write_bytes_interval: u64) -> FileIoStats {
        FileIoStats {
            pid: 10,
            process_start_time: 99,
            fd: 3,
            path: "/tmp/data".into(),
            read_bytes_interval,
            write_bytes_interval,
            cumulative_read: read_bytes_interval,
            cumulative_write: write_bytes_interval,
            cumulative_total: read_bytes_interval.saturating_add(write_bytes_interval),
            last_io_at: Instant::now(),
        }
    }

    #[test]
    fn read_only_operation_uses_short_label() {
        assert_eq!(file_stats(100, 0).operation_label(), "r");
    }

    #[test]
    fn write_only_operation_uses_short_label() {
        assert_eq!(file_stats(0, 100).operation_label(), "w");
    }

    #[test]
    fn mixed_operation_uses_short_label() {
        assert_eq!(file_stats(100, 100).operation_label(), "r,w");
    }

    #[test]
    fn read_and_write_events_update_the_correct_counters() {
        let now = Instant::now();
        let mut accumulator = FileIoAccumulator::default();

        accumulator.record_event(
            event(10, 3, IoOperation::Read, 1_024),
            99,
            "/tmp/data".into(),
            now,
        );
        accumulator.record_event(
            event(10, 3, IoOperation::Write, 2_048),
            99,
            "/tmp/data".into(),
            now,
        );

        let stats = accumulator.sorted_for_pid(10, 5);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].read_bytes_interval, 1_024);
        assert_eq!(stats[0].write_bytes_interval, 2_048);
        assert_eq!(stats[0].cumulative_read, 1_024);
        assert_eq!(stats[0].cumulative_write, 2_048);
        assert_eq!(stats[0].cumulative_total, 3_072);
        assert_eq!(stats[0].operation_label(), "r,w");
    }

    #[test]
    fn begin_interval_resets_only_interval_counters() {
        let now = Instant::now();
        let mut accumulator = FileIoAccumulator::default();
        accumulator.record_event(
            event(10, 3, IoOperation::Read, 512),
            99,
            "/tmp/data".into(),
            now,
        );

        accumulator.begin_interval();

        let visible = accumulator.sorted_for_pid(10, 5);
        assert_eq!(visible.len(), 1);
        let stats = visible[0];
        assert_eq!(stats.interval_total(), 0);
        assert_eq!(stats.cumulative_total, 512);
        assert_eq!(stats.operation_label(), "r");
    }

    #[test]
    fn file_stats_are_sorted_by_cumulative_total_and_limited() {
        let now = Instant::now();
        let mut accumulator = FileIoAccumulator::default();
        accumulator.record_event(
            event(10, 3, IoOperation::Read, 1_000),
            99,
            "/tmp/largest-cumulative".into(),
            now,
        );
        accumulator.record_event(
            event(10, 4, IoOperation::Write, 500),
            99,
            "/tmp/smaller-cumulative".into(),
            now,
        );
        accumulator.begin_interval();
        accumulator.record_event(
            event(10, 4, IoOperation::Write, 100),
            99,
            "/tmp/smaller-cumulative".into(),
            now + Duration::from_secs(1),
        );

        let stats = accumulator.sorted_for_pid(10, 1);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].path, "/tmp/largest-cumulative");
        assert_eq!(stats[0].write_bytes_interval, 0);
    }

    #[test]
    fn detail_retention_removes_stale_files() {
        let now = Instant::now();
        let mut accumulator = FileIoAccumulator::default();
        accumulator.record_event(
            event(10, 3, IoOperation::Read, 100),
            99,
            "/tmp/data".into(),
            now,
        );

        accumulator.retain_recent(now + Duration::from_secs(299), Duration::from_secs(300));
        assert_eq!(accumulator.sorted_for_pid(10, 5).len(), 1);

        accumulator.retain_recent(now + Duration::from_secs(300), Duration::from_secs(300));
        assert!(accumulator.sorted_for_pid(10, 5).is_empty());
    }

    #[test]
    fn unresolved_fd_uses_fallback_path() {
        assert_eq!(resolve_fd_path(u32::MAX, -1), "fd:-1 (unresolved)");
    }

    #[test]
    fn fallback_candidates_include_standard_streams() {
        let files = collect_open_file_candidates(std::process::id(), usize::MAX);

        for fd in 0..=2 {
            assert!(files.iter().any(|file| file.fd == fd), "missing fd {fd}");
        }
    }

    #[test]
    fn parses_process_start_time_after_complex_process_name() {
        let stat =
            "123 (name with ) parentheses) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242";
        assert_eq!(parse_process_start_time(stat).unwrap(), 4242);
    }

    #[test]
    fn parses_ring_buffer_event_layout() {
        let mut bytes = [0_u8; 24];
        bytes[0..4].copy_from_slice(&10_u32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&11_u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&3_i32.to_ne_bytes());
        bytes[12] = IoOperation::Write as u8;
        bytes[16..24].copy_from_slice(&4096_u64.to_ne_bytes());

        assert_eq!(
            parse_file_io_event(&bytes),
            Some(FileIoEvent {
                pid: 10,
                tid: 11,
                fd: 3,
                op: IoOperation::Write as u8,
                bytes: 4096,
            })
        );
    }
}
