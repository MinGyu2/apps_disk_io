# apps_disk_io

`apps_disk_io`는 Linux에서 실행 중인 프로세스별 디스크 읽기/쓰기 속도와 누적량을 표시하는 CLI 모니터링 도구입니다. 기본 모드는 `/proc/<pid>/io`를 사용하고, `--detail` 모드는 Aya/eBPF로 syscall 이벤트를 수집해 파일별 I/O를 함께 표시합니다.

기본 정렬은 현재 읽기/쓰기 속도의 합계(`total_bps`)가 큰 순서입니다. `--sort cumulative`를 사용하면 실행 후 누적 I/O가 큰 순서로 볼 수 있습니다. 정렬 값이 같으면 PID가 작은 프로세스가 먼저 표시됩니다.

## 빌드

Rust toolchain이 설치된 Linux 환경에서 빌드합니다.

```bash
git clone https://github.com/MinGyu2/apps_disk_io.git
cd apps_disk_io
cargo build --release
```

eBPF 오브젝트 빌드에는 clang과 clang의 BPF target 지원이 필요할 수 있습니다. Debian/Ubuntu 계열에서는 `/usr/include/<triple>` multiarch 헤더 경로가 필요할 수 있습니다. 해당 환경이 없으면 기본 모드는 사용할 수 있지만 eBPF 기반 detail 이벤트 수집은 사용할 수 없습니다.

## 실행

기본 실행:

```bash
./target/release/apps_disk_io
```

화면 갱신 주기를 1000ms로 지정:

```bash
./target/release/apps_disk_io --interval 1000
```

누적 I/O 기준으로 정렬:

```bash
./target/release/apps_disk_io --sort cumulative
```

파일별 I/O detail 표시:

```bash
sudo ./target/release/apps_disk_io --detail
```

detail과 현재 열린 파일 디스크립터 목록을 함께 표시:

```bash
sudo ./target/release/apps_disk_io --detail --fd
```

`--fd` 목록은 열린 파일 디스크립터를 보여줄 뿐, 각 파일에서 실제 read/write가 발생했다는 의미는 아닙니다.

## 측정 방식의 차이

기본 프로세스 통계와 detail 파일 통계는 측정 지점이 다릅니다.

- 기본 모드는 `/proc/<pid>/io`의 `read_bytes`와 `write_bytes`를 사용합니다. 이 값은 실제 스토리지 계층에서 읽거나 스토리지 계층으로 전달된 바이트에 가깝습니다.
- detail 모드는 추적한 syscall의 반환 바이트를 파일별로 누적합니다. 따라서 page cache에서 처리된 읽기 바이트도 포함될 수 있습니다.
- 측정 의미와 수집 시점이 다르므로 기본 프로세스별 합계와 detail 파일별 합계가 완전히 일치하지 않을 수 있습니다.

eBPF 프로그램을 로드하고 tracepoint에 연결하려면 root 권한 또는 환경에 따라 `CAP_BPF`와 `CAP_PERFMON` capability가 필요할 수 있습니다.

## detail 모드 coverage

현재 eBPF detail 모드는 다음 syscall만 추적합니다.

- `read`
- `write`
- `pread64`
- `pwrite64`
- `readv`
- `writev`

따라서 다음 경로로 수행되는 I/O는 파일별 통계에서 누락될 수 있습니다.

- `preadv`, `pwritev`, `preadv2`, `pwritev2`
- `copy_file_range`
- `sendfile`
- `io_uring` 기반 I/O
- `mmap` 기반 I/O
