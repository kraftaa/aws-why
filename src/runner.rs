use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

const ERROR_CAPTURE_LIMIT: usize = 1024 * 1024;
const DIAGNOSTIC_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
const STDOUT_SPOOL_LIMIT: usize = 64 * 1024 * 1024;
const STDERR_SPOOL_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct CommandRun {
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stderr_replay_truncated: bool,
    stdout_spool: Option<NamedTempFile>,
    stderr_spool: Option<NamedTempFile>,
}

impl CommandRun {
    pub fn replay_stdout(&mut self) -> io::Result<()> {
        replay(&mut self.stdout_spool, &mut io::stdout())
    }

    pub fn replay_stderr(&mut self) -> io::Result<()> {
        replay(&mut self.stderr_spool, &mut io::stderr())
    }
}

fn replay(spool: &mut Option<NamedTempFile>, output: &mut impl Write) -> io::Result<()> {
    if let Some(spool) = spool {
        spool.as_file_mut().seek(SeekFrom::Start(0))?;
        io::copy(spool.as_file_mut(), output)?;
        output.flush()?;
    }
    Ok(())
}

fn normalized_exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return 128 + status.signal().unwrap_or(0);
    }
    #[allow(unreachable_code)]
    1
}

struct CappedFileWriter {
    file: File,
    remaining: usize,
    truncated: Arc<AtomicBool>,
}

impl Write for CappedFileWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.remaining);
        if count > 0 {
            self.file.write_all(&buffer[..count])?;
            self.remaining -= count;
        }
        if count < buffer.len() {
            self.truncated.store(true, Ordering::Relaxed);
        }
        // Report the entire buffer consumed; excess bytes are intentionally discarded.
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug)]
struct PumpResult {
    captured: Vec<u8>,
    capture_truncated: bool,
}

fn pump<R>(
    mut reader: R,
    mut writer: Box<dyn Write + Send>,
    capture_limit: usize,
) -> io::Result<PumpResult>
where
    R: Read,
{
    let mut captured = VecDeque::with_capacity(capture_limit.min(16 * 1024));
    let mut capture_truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count])?;
        writer.flush()?;
        if capture_limit == 0 {
            continue;
        }
        for byte in &buffer[..count] {
            if captured.len() == capture_limit {
                captured.pop_front();
                capture_truncated = true;
            }
            captured.push_back(*byte);
        }
    }
    Ok(PumpResult {
        captured: captured.into(),
        capture_truncated,
    })
}

fn capped_spool(
    limit: usize,
) -> io::Result<(NamedTempFile, Box<dyn Write + Send>, Arc<AtomicBool>)> {
    let spool = NamedTempFile::new()?;
    let truncated = Arc::new(AtomicBool::new(false));
    let writer = CappedFileWriter {
        file: spool.reopen()?,
        remaining: limit,
        truncated: Arc::clone(&truncated),
    };
    Ok((spool, Box::new(writer), truncated))
}

/// Run the exact argv supplied by the user. stdin is inherited. In human mode,
/// stdout streams immediately while stderr is securely spooled so authorization
/// failures can be replaced with a redacted explanation. Machine mode securely
/// spools both streams to keep failure JSON parseable.
pub fn run_user_command(argv: &[String], human_mode: bool) -> io::Result<CommandRun> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    let (stdout_spool, stdout_writer, stdout_output_truncated) = if human_mode {
        (None, Box::new(io::stdout()) as Box<dyn Write + Send>, None)
    } else {
        let (spool, writer, truncated) = capped_spool(STDOUT_SPOOL_LIMIT)?;
        (Some(spool), writer, Some(truncated))
    };
    let (stderr_file, stderr_writer, stderr_output_truncated) = capped_spool(STDERR_SPOOL_LIMIT)?;
    let stdout_thread = thread::spawn(move || pump(stdout, stdout_writer, 0));
    let stderr_thread = thread::spawn(move || pump(stderr, stderr_writer, ERROR_CAPTURE_LIMIT));

    let status = child.wait()?;
    let stdout_result = stdout_thread
        .join()
        .map_err(|_| io::Error::other("stdout reader thread panicked"))??;
    let stderr_result = stderr_thread
        .join()
        .map_err(|_| io::Error::other("stderr reader thread panicked"))??;
    Ok(CommandRun {
        argv: argv.to_vec(),
        exit_code: normalized_exit_code(status),
        stdout: stdout_result.captured,
        stderr: stderr_result.captured,
        stdout_truncated: stdout_result.capture_truncated
            || stdout_output_truncated.is_some_and(|value| value.load(Ordering::Relaxed)),
        stderr_truncated: stderr_result.capture_truncated,
        stderr_replay_truncated: stderr_output_truncated.load(Ordering::Relaxed),
        stdout_spool,
        stderr_spool: Some(stderr_file),
    })
}

#[cfg(test)]
mod tests {
    use super::pump;
    #[cfg(unix)]
    use super::run_diagnostic;
    use std::io;
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    #[test]
    fn capture_keeps_only_the_bounded_tail() {
        let input = b"0123456789";
        let result = pump(&input[..], Box::new(io::sink()), 4).unwrap();
        assert_eq!(result.captured, b"6789");
        assert!(result.capture_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostics_ignore_configured_custom_endpoints() {
        let output = run_diagnostic(
            "/bin/sh",
            &[
                "-c".into(),
                "printf '%s' \"$AWS_IGNORE_CONFIGURED_ENDPOINT_URLS\"".into(),
            ],
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(output.stdout, b"true");
    }

    #[cfg(unix)]
    #[test]
    fn timeout_does_not_wait_for_descendants_holding_pipes() {
        let started = Instant::now();
        let result = run_diagnostic(
            "/bin/sh",
            &["-c".into(), "(sleep 1) & sleep 5".into()],
            Duration::from_millis(50),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}

#[derive(Debug)]
pub struct DiagnosticOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

pub fn run_diagnostic(
    executable: &str,
    args: &[OsString],
    timeout: Duration,
) -> io::Result<DiagnosticOutput> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("AWS_PAGER", "")
        .env("AWS_CLI_AUTO_PROMPT", "off")
        .env("AWS_CLI_ERROR_FORMAT", "json")
        .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
        .spawn()?;
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_thread =
        thread::spawn(move || pump(stdout_pipe, Box::new(io::sink()), DIAGNOSTIC_CAPTURE_LIMIT));
    let stderr_thread =
        thread::spawn(move || pump(stderr_pipe, Box::new(io::sink()), DIAGNOSTIC_CAPTURE_LIMIT));
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_thread
                .join()
                .map_err(|_| io::Error::other("diagnostic stdout reader panicked"))??;
            let stderr = stderr_thread
                .join()
                .map_err(|_| io::Error::other("diagnostic stderr reader panicked"))??;
            return Ok(DiagnosticOutput {
                success: status.success(),
                truncated: stdout.capture_truncated || stderr.capture_truncated,
                stdout: stdout.captured,
                stderr: stderr.captured,
            });
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let _ = child.wait();
            // A credential helper may have inherited a pipe. Detach the readers
            // so the configured timeout returns instead of waiting for descendants.
            drop(stdout_thread);
            drop(stderr_thread);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AWS diagnostic call timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}
