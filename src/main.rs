pub mod detail;

use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_INTERVAL_MS: u64 = 1_000;
const DEFAULT_RETAIN_EXITED_SECONDS: u64 = 30;
const DEFAULT_DETAIL_LIMIT: usize = 5;
const MAX_PROCESSES: usize = 20;

#[derive(Debug, Parser)]
#[command(
    name = "apps_disk_io",
    version,
    about = "실행 중인 프로세스별 디스크 I/O 속도를 표시합니다."
)]
struct Cli {
    /// 화면 갱신 주기(밀리초)
    #[arg(
        long,
        value_name = "MILLISECONDS",
        default_value_t = DEFAULT_INTERVAL_MS,
        value_parser = parse_interval
    )]
    interval: u64,

    /// 종료된 프로세스를 화면에 유지할 시간(초)
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = DEFAULT_RETAIN_EXITED_SECONDS
    )]
    retain_exited: u64,

    /// 열린 파일 디스크립터 후보를 프로세스 아래에 표시
    #[arg(long)]
    detail: bool,

    /// detail 모드에서 프로세스당 표시할 최대 파일 수
    #[arg(long, value_name = "COUNT", default_value_t = DEFAULT_DETAIL_LIMIT)]
    detail_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSample {
    name: String,
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct ProcessStats {
    pid: u32,
    name: String,
    read_bps: f64,
    write_bps: f64,
    total_bps: f64,
    cumulative_read: u64,
    cumulative_write: u64,
    cumulative_total: u64,
    last_seen: Instant,
    last_io_at: Option<Instant>,
    exited: bool,
}

fn parse_interval(value: &str) -> Result<u64, String> {
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("유효하지 않은 interval '{value}': 0보다 큰 정수를 입력하세요"))?;

    if milliseconds == 0 {
        return Err("유효하지 않은 interval '0': 0보다 큰 정수를 입력하세요".to_string());
    }

    Ok(milliseconds)
}

/// `/proc/<pid>/io`에서 실제 스토리지 계층까지 전달된 누적 바이트를 읽는다.
fn read_proc_io(pid: u32) -> io::Result<(u64, u64)> {
    let contents = fs::read_to_string(format!("/proc/{pid}/io"))?;
    parse_proc_io(&contents)
}

fn parse_proc_io(contents: &str) -> io::Result<(u64, u64)> {
    let mut read_bytes = None;
    let mut write_bytes = None;

    for line in contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        match key {
            "read_bytes" => read_bytes = Some(parse_io_value(value, key)?),
            "write_bytes" => write_bytes = Some(parse_io_value(value, key)?),
            _ => {}
        }
    }

    match (read_bytes, write_bytes) {
        (Some(read), Some(write)) => Ok((read, write)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "read_bytes 또는 write_bytes 항목이 없습니다",
        )),
    }
}

fn parse_io_value(value: &str, key: &str) -> io::Result<u64> {
    value.trim().parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{key} 값을 파싱할 수 없습니다: {error}"),
        )
    })
}

/// 읽을 수 있는 모든 프로세스의 현재 누적 I/O 값을 수집한다.
fn collect_samples() -> io::Result<HashMap<u32, ProcessSample>> {
    let mut samples = HashMap::new();

    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else {
            continue;
        };

        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };

        let Ok((read_bytes, write_bytes)) = read_proc_io(pid) else {
            continue;
        };
        let Ok(name) = read_process_name(pid) else {
            continue;
        };

        samples.insert(
            pid,
            ProcessSample {
                name,
                read_bytes,
                write_bytes,
            },
        );
    }

    Ok(samples)
}

fn read_process_name(pid: u32) -> io::Result<String> {
    let name = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("comm"))?;
    Ok(name.trim_end_matches(['\n', '\r']).to_string())
}

fn calculate_rates(
    previous: &HashMap<u32, ProcessSample>,
    current: &HashMap<u32, ProcessSample>,
    elapsed_seconds: f64,
    stats: &mut HashMap<u32, ProcessStats>,
    sampled_at: Instant,
    retain_exited: Duration,
) {
    debug_assert!(elapsed_seconds > 0.0);

    for (&pid, sample) in current {
        let (read_delta, write_delta) = match previous.get(&pid) {
            Some(previous_sample) => (
                // 카운터 감소(PID 재사용 또는 커널 카운터 초기화)는 0으로 처리한다.
                sample.read_bytes.saturating_sub(previous_sample.read_bytes),
                sample
                    .write_bytes
                    .saturating_sub(previous_sample.write_bytes),
            ),
            None => (0, 0),
        };

        let read_bps = read_delta as f64 / elapsed_seconds;
        let write_bps = write_delta as f64 / elapsed_seconds;
        let total_delta = read_delta.saturating_add(write_delta);

        if let Some(process_stats) = stats.get_mut(&pid) {
            process_stats.name.clone_from(&sample.name);
            process_stats.read_bps = read_bps;
            process_stats.write_bps = write_bps;
            process_stats.total_bps = read_bps + write_bps;
            process_stats.cumulative_read =
                process_stats.cumulative_read.saturating_add(read_delta);
            process_stats.cumulative_write =
                process_stats.cumulative_write.saturating_add(write_delta);
            process_stats.cumulative_total = process_stats
                .cumulative_read
                .saturating_add(process_stats.cumulative_write);
            process_stats.last_seen = sampled_at;
            process_stats.exited = false;

            if total_delta > 0 {
                process_stats.last_io_at = Some(sampled_at);
            }
        } else {
            stats.insert(
                pid,
                ProcessStats {
                    pid,
                    name: sample.name.clone(),
                    read_bps,
                    write_bps,
                    total_bps: read_bps + write_bps,
                    cumulative_read: read_delta,
                    cumulative_write: write_delta,
                    cumulative_total: total_delta,
                    last_seen: sampled_at,
                    last_io_at: (total_delta > 0).then_some(sampled_at),
                    exited: false,
                },
            );
        }
    }

    // 현재 샘플에서 사라진 프로세스는 속도를 0으로 만들고 보존 시간 후 제거한다.
    stats.retain(|pid, process_stats| {
        if current.contains_key(pid) {
            return true;
        }

        process_stats.read_bps = 0.0;
        process_stats.write_bps = 0.0;
        process_stats.total_bps = 0.0;
        process_stats.exited = true;

        sampled_at.duration_since(process_stats.last_seen) < retain_exited
    });
}

fn stats_for_display(stats: &HashMap<u32, ProcessStats>) -> Vec<&ProcessStats> {
    let mut processes: Vec<_> = stats
        .values()
        .filter(|process_stats| process_stats.cumulative_total > 0)
        .collect();

    processes.sort_unstable_by(|left, right| {
        right
            .cumulative_total
            .cmp(&left.cumulative_total)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    processes.truncate(MAX_PROCESSES);
    processes
}

fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    if bytes_per_sec >= GIB {
        format!("{:.1} GB/s", bytes_per_sec / GIB)
    } else if bytes_per_sec >= MIB {
        format!("{:.1} MB/s", bytes_per_sec / MIB)
    } else if bytes_per_sec >= KIB {
        format!("{:.1} KB/s", bytes_per_sec / KIB)
    } else {
        format!("{bytes_per_sec:.0} B/s")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;

    if bytes >= GIB {
        format!("{:.1} GB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

#[derive(Clone, Copy)]
struct DetailRenderContext<'a> {
    accumulator: &'a detail::FileIoAccumulator,
    fallback: &'a detail::FallbackDetails,
    event_source_error: Option<&'a str>,
    elapsed_seconds: f64,
    limit: usize,
}

impl DetailRenderContext<'_> {
    fn uses_fallback(self, processes: &[&ProcessStats]) -> bool {
        processes.is_empty()
            || processes.iter().any(|process_stats| {
                self.accumulator
                    .sorted_for_pid(process_stats.pid, self.limit)
                    .is_empty()
            })
    }
}

fn render<W: Write>(
    writer: &mut W,
    processes: &[&ProcessStats],
    interval: Duration,
    details: Option<DetailRenderContext<'_>>,
) -> io::Result<()> {
    // 화면을 지우고 커서를 왼쪽 위로 이동한다.
    write!(writer, "\x1b[2J\x1b[H")?;
    if let Some(details) = details {
        writeln!(
            writer,
            "Process disk I/O (interval: {} ms, top {}, detail: on)",
            interval.as_millis(),
            MAX_PROCESSES
        )?;
        if details.uses_fallback(processes) {
            writeln!(writer, "{}", detail::FALLBACK_NOTICE)?;
            if let Some(error) = details.event_source_error {
                writeln!(
                    writer,
                    "detail event source unavailable: {}",
                    sanitize_for_terminal(error)
                )?;
            }
        }
    } else {
        writeln!(
            writer,
            "Process disk I/O (interval: {} ms, top {})",
            interval.as_millis(),
            MAX_PROCESSES
        )?;
    }
    writeln!(
        writer,
        "{:<8} {:<25} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "PID", "NAME", "READ/s", "WRITE/s", "TOTAL/s", "CUM_READ", "CUM_WRITE", "CUM_TOTAL"
    )?;

    for process_stats in processes {
        let name = if process_stats.exited {
            format!("{} (exited)", process_stats.name)
        } else {
            process_stats.name.clone()
        };

        writeln!(
            writer,
            "{:<8} {:<25.25} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
            process_stats.pid,
            name,
            format_bytes_per_sec(process_stats.read_bps),
            format_bytes_per_sec(process_stats.write_bps),
            format_bytes_per_sec(process_stats.total_bps),
            format_bytes(process_stats.cumulative_read),
            format_bytes(process_stats.cumulative_write),
            format_bytes(process_stats.cumulative_total),
        )?;

        if let Some(details) = details {
            render_process_details(writer, process_stats, details)?;
        }
    }

    if processes.is_empty() {
        writeln!(writer, "현재 I/O를 수행 중인 프로세스가 없습니다.")?;
    }

    writer.flush()
}

fn render_process_details<W: Write>(
    writer: &mut W,
    process_stats: &ProcessStats,
    details: DetailRenderContext<'_>,
) -> io::Result<()> {
    let file_stats = details
        .accumulator
        .sorted_for_pid(process_stats.pid, details.limit);

    if file_stats.is_empty() {
        render_fallback_details(writer, process_stats, details.fallback)
    } else {
        render_file_io_details(writer, &file_stats, details.elapsed_seconds)
    }
}

fn render_file_io_details<W: Write>(
    writer: &mut W,
    files: &[&detail::FileIoStats],
    elapsed_seconds: f64,
) -> io::Result<()> {
    for (index, file) in files.iter().enumerate() {
        let branch = if index + 1 == files.len() {
            "└─"
        } else {
            "├─"
        };
        writeln!(
            writer,
            "         {branch} {}",
            format_file_io_detail(file, elapsed_seconds)
        )?;
    }

    Ok(())
}

fn format_file_io_detail(file: &detail::FileIoStats, elapsed_seconds: f64) -> String {
    debug_assert!(elapsed_seconds > 0.0);
    let mut fields = vec![format!("{:<3}", file.operation_label())];

    if file.read_bytes_interval > 0 {
        fields.push(format!(
            "r: {}",
            format_bytes_per_sec(file.read_bytes_interval as f64 / elapsed_seconds)
        ));
    }
    if file.write_bytes_interval > 0 {
        fields.push(format!(
            "w: {}",
            format_bytes_per_sec(file.write_bytes_interval as f64 / elapsed_seconds)
        ));
    }
    if file.cumulative_read > 0 {
        fields.push(format!("cum r: {}", format_bytes(file.cumulative_read)));
    }
    if file.cumulative_write > 0 {
        fields.push(format!("cum w: {}", format_bytes(file.cumulative_write)));
    }
    fields.push(sanitize_for_terminal(&file.path));

    fields.join("   ")
}

fn render_fallback_details<W: Write>(
    writer: &mut W,
    process_stats: &ProcessStats,
    details: &detail::FallbackDetails,
) -> io::Result<()> {
    let files = details.get(&process_stats.pid);

    if process_stats.exited {
        return writeln!(
            writer,
            "         └─ open-fd   file descriptors unavailable (process exited)"
        );
    }

    let Some(files) = files.filter(|files| !files.is_empty()) else {
        return writeln!(writer, "         └─ open-fd   no readable file descriptors");
    };

    for (index, file) in files.iter().enumerate() {
        let branch = if index + 1 == files.len() {
            "└─"
        } else {
            "├─"
        };
        writeln!(
            writer,
            "         {branch} open-fd   fd={:<4} {}",
            file.fd,
            sanitize_for_terminal(&file.path)
        )?;
    }

    Ok(())
}

fn sanitize_for_terminal(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn run(
    interval: Duration,
    retain_exited: Duration,
    detail_enabled: bool,
    detail_limit: usize,
) -> io::Result<()> {
    let mut previous = collect_samples()?;
    let mut previous_sampled_at = Instant::now();
    let mut stats = HashMap::new();
    let mut file_io_accumulator = detail_enabled.then(detail::FileIoAccumulator::default);
    let (event_source, event_source_error) = if detail_enabled {
        match detail::FileIoEventSource::start() {
            Ok(source) => (Some(source), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();

    loop {
        if let Some(accumulator) = file_io_accumulator.as_mut() {
            accumulator.begin_interval();
        }
        thread::sleep(interval);

        if let (Some(event_source), Some(accumulator)) =
            (&event_source, file_io_accumulator.as_mut())
        {
            while let Some(resolved) = event_source.try_recv() {
                accumulator.record_event(
                    resolved.event,
                    resolved.process_start_time,
                    resolved.path,
                    resolved.occurred_at,
                );
            }
        }

        let current = collect_samples()?;
        let sampled_at = Instant::now();
        let elapsed_seconds = sampled_at.duration_since(previous_sampled_at).as_secs_f64();
        calculate_rates(
            &previous,
            &current,
            elapsed_seconds,
            &mut stats,
            sampled_at,
            retain_exited,
        );
        let processes = stats_for_display(&stats);
        let fallback_details = detail_enabled.then(|| {
            detail::collect_fallback_details(
                processes
                    .iter()
                    .filter(|process_stats| !process_stats.exited)
                    .map(|process_stats| process_stats.pid),
                detail_limit,
            )
        });
        let details = match (&file_io_accumulator, &fallback_details) {
            (Some(accumulator), Some(fallback)) => Some(DetailRenderContext {
                accumulator,
                fallback,
                event_source_error: event_source_error.as_deref(),
                elapsed_seconds,
                limit: detail_limit,
            }),
            _ => None,
        };

        render(&mut output, &processes, interval, details)?;

        previous = current;
        previous_sampled_at = sampled_at;
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let interval = Duration::from_millis(cli.interval);
    let retain_exited = Duration::from_secs(cli.retain_exited);

    match run(interval, retain_exited, cli.detail, cli.detail_limit) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("오류: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, read_bytes: u64, write_bytes: u64) -> ProcessSample {
        ProcessSample {
            name: name.into(),
            read_bytes,
            write_bytes,
        }
    }

    fn file_stats(
        read_bytes_interval: u64,
        write_bytes_interval: u64,
        cumulative_read: u64,
        cumulative_write: u64,
        path: &str,
    ) -> detail::FileIoStats {
        detail::FileIoStats {
            pid: 10,
            process_start_time: 99,
            fd: 3,
            path: path.into(),
            read_bytes_interval,
            write_bytes_interval,
            cumulative_read,
            cumulative_write,
            cumulative_total: cumulative_read.saturating_add(cumulative_write),
            last_io_at: Instant::now(),
        }
    }

    fn process_stats() -> ProcessStats {
        ProcessStats {
            pid: 10,
            name: "worker".into(),
            read_bps: 0.0,
            write_bps: 0.0,
            total_bps: 0.0,
            cumulative_read: 1_024,
            cumulative_write: 2_048,
            cumulative_total: 3_072,
            last_seen: Instant::now(),
            last_io_at: Some(Instant::now()),
            exited: false,
        }
    }

    fn render_accumulated_file_io(accumulator: &detail::FileIoAccumulator) -> String {
        let fallback = HashMap::new();
        let mut output = Vec::new();

        render_process_details(
            &mut output,
            &process_stats(),
            DetailRenderContext {
                accumulator,
                fallback: &fallback,
                event_source_error: None,
                elapsed_seconds: 1.0,
                limit: 5,
            },
        )
        .unwrap();

        String::from_utf8(output).unwrap()
    }

    #[test]
    fn interval_must_be_a_positive_integer() {
        assert_eq!(parse_interval("1000"), Ok(1000));
        assert!(parse_interval("0").is_err());
        assert!(parse_interval("abc").is_err());
    }

    #[test]
    fn parses_read_and_write_bytes() {
        let contents = "rchar: 100\nwchar: 200\nread_bytes: 4096\nwrite_bytes: 8192\n";
        assert_eq!(parse_proc_io(contents).unwrap(), (4096, 8192));
    }

    #[test]
    fn process_with_zero_delta_remains_visible() {
        let started_at = Instant::now();
        let previous = HashMap::from([(10, sample("worker", 100, 200))]);
        let current = HashMap::from([(10, sample("worker", 1_100, 2_200))]);
        let mut stats = HashMap::new();

        calculate_rates(
            &previous,
            &current,
            1.0,
            &mut stats,
            started_at,
            Duration::from_secs(30),
        );
        calculate_rates(
            &current,
            &current,
            1.0,
            &mut stats,
            started_at + Duration::from_secs(1),
            Duration::from_secs(30),
        );

        let process_stats = stats.get(&10).unwrap();
        assert_eq!(process_stats.total_bps, 0.0);
        assert_eq!(process_stats.cumulative_total, 3_000);
        assert_eq!(stats_for_display(&stats)[0].pid, 10);
    }

    #[test]
    fn process_without_any_io_is_not_displayed() {
        let sampled_at = Instant::now();
        let samples = HashMap::from([(10, sample("idle", 100, 200))]);
        let mut stats = HashMap::new();

        calculate_rates(
            &samples,
            &samples,
            1.0,
            &mut stats,
            sampled_at,
            Duration::from_secs(30),
        );

        assert!(stats.contains_key(&10));
        assert!(stats_for_display(&stats).is_empty());
    }

    #[test]
    fn deltas_increase_cumulative_totals() {
        let sampled_at = Instant::now();
        let previous = HashMap::from([(10, sample("writer", 1_000, 500))]);
        let current = HashMap::from([(10, sample("writer", 3_000, 1_500))]);
        let mut stats = HashMap::new();

        calculate_rates(
            &previous,
            &current,
            2.0,
            &mut stats,
            sampled_at,
            Duration::from_secs(30),
        );

        let process_stats = stats.get(&10).unwrap();
        assert_eq!(process_stats.read_bps, 1_000.0);
        assert_eq!(process_stats.write_bps, 500.0);
        assert_eq!(process_stats.cumulative_read, 2_000);
        assert_eq!(process_stats.cumulative_write, 1_000);
        assert_eq!(process_stats.cumulative_total, 3_000);
        assert_eq!(process_stats.last_io_at, Some(sampled_at));
    }

    #[test]
    fn exited_process_is_removed_after_retention_period() {
        let started_at = Instant::now();
        let previous = HashMap::from([(10, sample("short-lived", 0, 0))]);
        let current = HashMap::from([(10, sample("short-lived", 1_024, 0))]);
        let empty = HashMap::new();
        let retain_exited = Duration::from_secs(30);
        let mut stats = HashMap::new();

        calculate_rates(
            &previous,
            &current,
            1.0,
            &mut stats,
            started_at,
            retain_exited,
        );
        calculate_rates(
            &current,
            &empty,
            1.0,
            &mut stats,
            started_at + Duration::from_secs(29),
            retain_exited,
        );

        assert!(stats.get(&10).unwrap().exited);

        calculate_rates(
            &empty,
            &empty,
            1.0,
            &mut stats,
            started_at + Duration::from_secs(30),
            retain_exited,
        );

        assert!(!stats.contains_key(&10));
    }

    #[test]
    fn processes_are_sorted_by_cumulative_total() {
        let sampled_at = Instant::now();
        let previous = HashMap::from([(10, sample("small", 0, 0)), (20, sample("large", 0, 0))]);
        let current = HashMap::from([
            (10, sample("small", 100, 50)),
            (20, sample("large", 200, 300)),
        ]);
        let mut stats = HashMap::new();

        calculate_rates(
            &previous,
            &current,
            1.0,
            &mut stats,
            sampled_at,
            Duration::from_secs(30),
        );

        let processes = stats_for_display(&stats);
        assert_eq!(processes[0].pid, 20);
        assert_eq!(processes[1].pid, 10);
    }

    #[test]
    fn formats_binary_byte_units() {
        assert_eq!(format_bytes_per_sec(0.0), "0 B/s");
        assert_eq!(format_bytes_per_sec(1_536.0), "1.5 KB/s");
        assert_eq!(format_bytes_per_sec(2.0 * 1024.0 * 1024.0), "2.0 MB/s");
        assert_eq!(
            format_bytes_per_sec(3.0 * 1024.0 * 1024.0 * 1024.0),
            "3.0 GB/s"
        );
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1_536), "1.5 KB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn formats_mixed_file_io_with_separate_rates_and_cumulative_values() {
        let file = file_stats(
            1024 * 1024,
            2 * 1024,
            10 * 1024 * 1024,
            512 * 1024,
            "/tmp/data",
        );

        let output = format_file_io_detail(&file, 1.0);

        assert!(output.starts_with("r,w"));
        assert!(output.contains("r: 1.0 MB/s"));
        assert!(output.contains("w: 2.0 KB/s"));
        assert!(output.contains("cum r: 10.0 MB"));
        assert!(output.contains("cum w: 512.0 KB"));
        assert!(output.ends_with("/tmp/data"));
    }

    #[test]
    fn actual_file_stats_are_rendered_instead_of_fallback_entries() {
        let now = Instant::now();
        let mut accumulator = detail::FileIoAccumulator::default();
        accumulator.record_event(
            detail::FileIoEvent {
                pid: 10,
                tid: 10,
                fd: 3,
                op: detail::IoOperation::Read as u8,
                bytes: 1_024,
            },
            99,
            "/tmp/data".into(),
            now,
        );
        let fallback = HashMap::from([(
            10,
            vec![detail::OpenFileCandidate {
                fd: 4,
                path: "/tmp/fallback".into(),
            }],
        )]);
        let mut output = Vec::new();

        render_process_details(
            &mut output,
            &process_stats(),
            DetailRenderContext {
                accumulator: &accumulator,
                fallback: &fallback,
                event_source_error: None,
                elapsed_seconds: 1.0,
                limit: 5,
            },
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("r: 1.0 KB/s"));
        assert!(output.contains("cum r: 1.0 KB"));
        assert!(!output.contains("open-fd"));
        assert!(!output.contains("/tmp/fallback"));
    }

    #[test]
    fn write_event_renders_write_detail() {
        let mut accumulator = detail::FileIoAccumulator::default();
        accumulator.record_event(
            detail::FileIoEvent {
                pid: 10,
                tid: 10,
                fd: 4,
                op: detail::IoOperation::Write as u8,
                bytes: 2 * 1024,
            },
            99,
            "/tmp/output".into(),
            Instant::now(),
        );

        let output = render_accumulated_file_io(&accumulator);
        assert!(output.contains("└─ w"));
        assert!(output.contains("w: 2.0 KB/s"));
        assert!(output.contains("cum w: 2.0 KB"));
        assert!(!output.contains("open-fd"));
    }

    #[test]
    fn mixed_events_render_both_read_and_write_details() {
        let mut accumulator = detail::FileIoAccumulator::default();
        for (operation, bytes) in [
            (detail::IoOperation::Read, 1024),
            (detail::IoOperation::Write, 2 * 1024),
        ] {
            accumulator.record_event(
                detail::FileIoEvent {
                    pid: 10,
                    tid: 10,
                    fd: 5,
                    op: operation as u8,
                    bytes,
                },
                99,
                "/tmp/mixed".into(),
                Instant::now(),
            );
        }

        let output = render_accumulated_file_io(&accumulator);
        assert!(output.contains("└─ r,w"));
        assert!(output.contains("r: 1.0 KB/s"));
        assert!(output.contains("w: 2.0 KB/s"));
        assert!(!output.contains("open-fd"));
    }

    #[test]
    fn fallback_details_never_claim_read_write_or_speed_values() {
        let fallback = HashMap::from([(
            10,
            vec![detail::OpenFileCandidate {
                fd: 3,
                path: "/tmp/data".into(),
            }],
        )]);
        let mut output = Vec::new();

        render_fallback_details(&mut output, &process_stats(), &fallback).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("open-fd   fd=3"));
        assert!(!output.contains("r: "));
        assert!(!output.contains("w: "));
        assert!(!output.contains("r,w"));
        assert!(!output.contains("B/s"));
        assert!(!output.contains("KB/s"));
        assert!(!output.contains("MB/s"));
    }

    #[test]
    fn parses_retain_exited_option() {
        let cli =
            Cli::try_parse_from(["apps_disk_io", "--interval", "500", "--retain-exited", "60"])
                .unwrap();

        assert_eq!(cli.interval, 500);
        assert_eq!(cli.retain_exited, 60);
        assert!(!cli.detail);
        assert_eq!(cli.detail_limit, DEFAULT_DETAIL_LIMIT);
    }

    #[test]
    fn parses_detail_options() {
        let cli =
            Cli::try_parse_from(["apps_disk_io", "--detail", "--detail-limit", "10"]).unwrap();

        assert!(cli.detail);
        assert_eq!(cli.detail_limit, 10);
    }
}
