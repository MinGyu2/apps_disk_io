use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_INTERVAL_MS: u64 = 1_000;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessSample {
    name: String,
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Debug, PartialEq)]
struct ProcessRate {
    pid: u32,
    name: String,
    read_bytes_per_sec: f64,
    write_bytes_per_sec: f64,
    total_bytes_per_sec: f64,
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
) -> Vec<ProcessRate> {
    let mut rates = Vec::new();

    for (&pid, sample) in current {
        let Some(previous_sample) = previous.get(&pid) else {
            continue;
        };

        // 카운터 감소(PID 재사용 또는 커널 카운터 초기화)는 0으로 처리한다.
        let read_delta = sample.read_bytes.saturating_sub(previous_sample.read_bytes);
        let write_delta = sample
            .write_bytes
            .saturating_sub(previous_sample.write_bytes);

        if read_delta == 0 && write_delta == 0 {
            continue;
        }

        let read_bytes_per_sec = read_delta as f64 / elapsed_seconds;
        let write_bytes_per_sec = write_delta as f64 / elapsed_seconds;

        rates.push(ProcessRate {
            pid,
            name: sample.name.clone(),
            read_bytes_per_sec,
            write_bytes_per_sec,
            total_bytes_per_sec: read_bytes_per_sec + write_bytes_per_sec,
        });
    }

    rates.sort_unstable_by(|left, right| {
        right
            .total_bytes_per_sec
            .total_cmp(&left.total_bytes_per_sec)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    rates.truncate(MAX_PROCESSES);
    rates
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

fn render<W: Write>(writer: &mut W, rates: &[ProcessRate], interval: Duration) -> io::Result<()> {
    // 화면을 지우고 커서를 왼쪽 위로 이동한다.
    write!(writer, "\x1b[2J\x1b[H")?;
    writeln!(
        writer,
        "Process disk I/O (interval: {} ms, top {})",
        interval.as_millis(),
        MAX_PROCESSES
    )?;
    writeln!(
        writer,
        "{:<8} {:<25} {:>14} {:>14} {:>14}",
        "PID", "NAME", "READ", "WRITE", "TOTAL"
    )?;

    for rate in rates {
        writeln!(
            writer,
            "{:<8} {:<25.25} {:>14} {:>14} {:>14}",
            rate.pid,
            rate.name,
            format_bytes_per_sec(rate.read_bytes_per_sec),
            format_bytes_per_sec(rate.write_bytes_per_sec),
            format_bytes_per_sec(rate.total_bytes_per_sec),
        )?;
    }

    if rates.is_empty() {
        writeln!(writer, "현재 I/O를 수행 중인 프로세스가 없습니다.")?;
    }

    writer.flush()
}

fn run(interval: Duration) -> io::Result<()> {
    let mut previous = collect_samples()?;
    let mut previous_sampled_at = Instant::now();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    loop {
        thread::sleep(interval);

        let current = collect_samples()?;
        let sampled_at = Instant::now();
        let elapsed_seconds = sampled_at.duration_since(previous_sampled_at).as_secs_f64();
        let rates = calculate_rates(&previous, &current, elapsed_seconds);

        render(&mut output, &rates, interval)?;

        previous = current;
        previous_sampled_at = sampled_at;
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let interval = Duration::from_millis(cli.interval);

    match run(interval) {
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
    fn calculates_and_sorts_non_zero_rates() {
        let previous = HashMap::from([
            (
                10,
                ProcessSample {
                    name: "reader".into(),
                    read_bytes: 1_000,
                    write_bytes: 500,
                },
            ),
            (
                20,
                ProcessSample {
                    name: "idle".into(),
                    read_bytes: 100,
                    write_bytes: 100,
                },
            ),
        ]);
        let current = HashMap::from([
            (
                10,
                ProcessSample {
                    name: "reader".into(),
                    read_bytes: 3_000,
                    write_bytes: 1_500,
                },
            ),
            (
                20,
                ProcessSample {
                    name: "idle".into(),
                    read_bytes: 100,
                    write_bytes: 100,
                },
            ),
        ]);

        let rates = calculate_rates(&previous, &current, 2.0);

        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].pid, 10);
        assert_eq!(rates[0].read_bytes_per_sec, 1_000.0);
        assert_eq!(rates[0].write_bytes_per_sec, 500.0);
        assert_eq!(rates[0].total_bytes_per_sec, 1_500.0);
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
    }
}
