use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CommandRun {
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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

fn pump<R, W>(mut reader: R, mut writer: Option<W>) -> io::Result<Vec<u8>>
where
    R: Read,
    W: Write,
{
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        captured.extend_from_slice(&buffer[..count]);
        if let Some(output) = writer.as_mut() {
            output.write_all(&buffer[..count])?;
            output.flush()?;
        }
    }
    Ok(captured)
}

/// Run the exact argv supplied by the user. stdin is inherited. stdout and
/// stderr are captured, and optionally streamed unchanged as they arrive.
pub fn run_user_command(argv: &[String], stream: bool) -> io::Result<CommandRun> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_thread = thread::spawn(move || {
        if stream {
            pump(stdout, Some(io::stdout()))
        } else {
            pump::<_, io::Sink>(stdout, None)
        }
    });
    let stderr_thread = thread::spawn(move || {
        if stream {
            pump(stderr, Some(io::stderr()))
        } else {
            pump::<_, io::Sink>(stderr, None)
        }
    });

    let status = child.wait()?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| io::Error::other("stdout reader thread panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| io::Error::other("stderr reader thread panicked"))??;
    Ok(CommandRun {
        argv: argv.to_vec(),
        exit_code: normalized_exit_code(status),
        stdout,
        stderr,
    })
}

#[derive(Debug)]
pub struct DiagnosticOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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
        .spawn()?;
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let stdout_thread = thread::spawn(move || pump::<_, io::Sink>(stdout_pipe, None));
    let stderr_thread = thread::spawn(move || pump::<_, io::Sink>(stderr_pipe, None));
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
                stdout,
                stderr,
            });
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AWS diagnostic call timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}
