use std::collections::HashMap;
use std::fs;
use std::time::Instant;

pub const FALLBACK_NOTICE: &str =
    "detail fallback mode: showing open file descriptors, not actual per-file I/O.";

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
        match (self.read_bytes_interval > 0, self.write_bytes_interval > 0) {
            (true, true) => "read/write",
            (true, false) => "read",
            (false, true) => "write",
            (false, false) => "idle",
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
            .filter(|stats| stats.pid == pid && stats.interval_total() > 0)
            .collect();

        stats.sort_unstable_by(|left, right| {
            right
                .interval_total()
                .cmp(&left.interval_total())
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
        assert_eq!(stats[0].operation_label(), "read/write");
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

        assert!(accumulator.sorted_for_pid(10, 5).is_empty());
        let stats = accumulator.stats.values().next().unwrap();
        assert_eq!(stats.cumulative_total, 512);
    }

    #[test]
    fn file_stats_are_sorted_by_interval_total_and_limited() {
        let now = Instant::now();
        let mut accumulator = FileIoAccumulator::default();
        accumulator.record_event(
            event(10, 3, IoOperation::Read, 100),
            99,
            "/tmp/small".into(),
            now,
        );
        accumulator.record_event(
            event(10, 4, IoOperation::Write, 500),
            99,
            "/tmp/large".into(),
            now,
        );

        let stats = accumulator.sorted_for_pid(10, 1);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].path, "/tmp/large");
    }

    #[test]
    fn unresolved_fd_uses_fallback_path() {
        assert_eq!(resolve_fd_path(u32::MAX, -1), "fd:-1 (unresolved)");
    }
}
