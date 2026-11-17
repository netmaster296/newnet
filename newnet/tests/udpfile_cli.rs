// The udpfile binary driven as two real processes over loopback UDP.

use std::io::Read;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn udpfile() -> Command {
    Command::new(env!("CARGO_BIN_EXE_udpfile"))
}

fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    drop(s);
    port
}

fn temp_path(test: &str, tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("udpfile_cli_{}_{test}_{tag}", std::process::id()));
    p
}

fn part_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".part");
    PathBuf::from(s)
}

fn spawn(args: &[String]) -> Child {
    udpfile()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

// Owns the spawned children and the temp files of one test: when the test
// ends, by return or by panic, any child still running is killed and every
// registered file is removed, so nothing is left behind.
struct Guard {
    children: Vec<Child>,
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl Guard {
    fn new() -> Guard {
        Guard { children: Vec::new(), files: Vec::new(), dirs: Vec::new() }
    }

    fn spawn(&mut self, args: &[String]) -> usize {
        self.children.push(spawn(args));
        self.children.len() - 1
    }

    // Like spawn, but the child's stderr is piped so the test can read it
    // after the child exits.
    fn spawn_stderr(&mut self, args: &[String]) -> usize {
        let child = udpfile()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        self.children.push(child);
        self.children.len() - 1
    }

    fn file(&mut self, p: &Path) {
        self.files.push(p.to_path_buf());
    }

    // Like file, for a directory the test may create at the path: removed
    // recursively when the guard drops.
    fn dir(&mut self, p: &Path) {
        self.dirs.push(p.to_path_buf());
    }

    fn wait_exit(&mut self, idx: usize, secs: u64) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            match self.children[idx].try_wait().unwrap() {
                Some(status) => return status.code().unwrap_or(-1),
                None => {
                    if Instant::now() >= deadline {
                        let _ = self.children[idx].kill();
                        let _ = self.children[idx].wait();
                        panic!("child did not exit within {secs} s");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn recv_args(port: u16, out: &Path, timeout: &str) -> Vec<String> {
    vec![
        "recv".into(),
        "--name".into(),
        "bob".into(),
        "--seed".into(),
        "2".into(),
        "--peer".into(),
        "alice".into(),
        "--peer-seed".into(),
        "1".into(),
        "--listen".into(),
        format!("127.0.0.1:{port}"),
        "--out".into(),
        out.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        timeout.into(),
    ]
}

fn send_args(port: u16, input: &Path, peer_seed: &str, timeout: &str) -> Vec<String> {
    vec![
        "send".into(),
        "--name".into(),
        "alice".into(),
        "--seed".into(),
        "1".into(),
        "--peer".into(),
        "bob".into(),
        "--peer-seed".into(),
        peer_seed.into(),
        "--to".into(),
        format!("127.0.0.1:{port}"),
        "--file".into(),
        input.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        timeout.into(),
    ]
}

fn sample_data() -> Vec<u8> {
    (0..1_500_000u64)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8)
        .collect()
}

#[test]
fn a_file_crosses_between_two_processes() {
    let mut g = Guard::new();
    let input = temp_path("a_file_crosses_between_two_processes", "in");
    let output = temp_path("a_file_crosses_between_two_processes", "out");
    g.file(&input);
    g.file(&output);
    let data = sample_data();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let r = g.spawn(&recv_args(port, &output, "55"));
    let s = g.spawn(&send_args(port, &input, "2", "55"));

    let rc_send = g.wait_exit(s, 60);
    let rc_recv = g.wait_exit(r, 60);
    let got = std::fs::read(&output).unwrap_or_default();
    assert_eq!(rc_send, 0, "send must exit 0");
    assert_eq!(rc_recv, 0, "recv must exit 0");
    assert_eq!(got, data, "the output file must equal the input file");
}

// The sender keeps retrying its handshake: a receiver that starts three
// seconds late must still complete the transfer.
#[test]
fn the_receiver_may_start_three_seconds_late() {
    let mut g = Guard::new();
    let input = temp_path("the_receiver_may_start_three_seconds_late", "in");
    let output = temp_path("the_receiver_may_start_three_seconds_late", "out");
    g.file(&input);
    g.file(&output);
    let data: Vec<u8> = (0..200_000u64)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8)
        .collect();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let s = g.spawn(&send_args(port, &input, "2", "40"));
    std::thread::sleep(Duration::from_secs(3));
    let r = g.spawn(&recv_args(port, &output, "40"));

    let rc_send = g.wait_exit(s, 90);
    let rc_recv = g.wait_exit(r, 90);
    let got = std::fs::read(&output).unwrap_or_default();
    assert_eq!(rc_send, 0, "send must exit 0");
    assert_eq!(rc_recv, 0, "recv must exit 0");
    assert_eq!(got, data, "the output file must equal the input file");
}

#[test]
fn a_wrong_peer_key_transfers_nothing() {
    let mut g = Guard::new();
    let input = temp_path("a_wrong_peer_key_transfers_nothing", "in");
    let output = temp_path("a_wrong_peer_key_transfers_nothing", "out");
    g.file(&input);
    g.file(&output);
    let data = sample_data();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let r = g.spawn_stderr(&recv_args(port, &output, "3"));
    let s = g.spawn_stderr(&send_args(port, &input, "999", "3"));

    let rc_send = g.wait_exit(s, 30);
    let rc_recv = g.wait_exit(r, 30);
    let mut send_err = String::new();
    let mut recv_err = String::new();
    g.children[s].stderr.as_mut().unwrap().read_to_string(&mut send_err).unwrap();
    g.children[r].stderr.as_mut().unwrap().read_to_string(&mut recv_err).unwrap();
    let existed = output.exists();
    assert_eq!(rc_send, 1, "send with a wrong peer key must exit 1");
    assert_eq!(rc_recv, 1, "recv must exit 1");
    assert!(!existed, "the output file must not exist");
    assert!(recv_err.contains("timed out"), "recv stderr must report the timeout, got: {recv_err}");
    assert!(
        send_err.contains("timed out") || send_err.contains("peer did not answer"),
        "send stderr must report the failure, got: {send_err}"
    );
    assert!(
        !send_err.contains("cannot bind") && !send_err.contains("cannot read"),
        "send must not fail on bind or read, got: {send_err}"
    );
    assert!(
        !recv_err.contains("cannot bind") && !recv_err.contains("cannot read"),
        "recv must not fail on bind or read, got: {recv_err}"
    );
}

#[test]
fn nothing_is_left_at_the_output_path_on_failure() {
    let mut g = Guard::new();
    let input = temp_path("nothing_is_left_at_the_output_path_on_failure", "in");
    let output = temp_path("nothing_is_left_at_the_output_path_on_failure", "out");
    let part = part_path(&output);
    g.file(&input);
    g.file(&output);
    g.file(&part);
    let data = sample_data();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let r = g.spawn(&recv_args(port, &output, "3"));
    let s = g.spawn(&send_args(port, &input, "999", "3"));

    let rc_send = g.wait_exit(s, 30);
    let rc_recv = g.wait_exit(r, 30);
    assert_eq!(rc_send, 1, "send with a wrong peer key must exit 1");
    assert_eq!(rc_recv, 1, "recv must exit 1");
    assert!(!output.exists(), "the output file must not exist after a failed run");
    assert!(!part.exists(), "no .part file may be left after a failed run");
}

#[test]
fn bad_arguments_exit_with_code_2() {
    let mut g = Guard::new();
    let c = g.spawn(&["recv".into(), "--name".into(), "bob".into()]);
    let code = g.wait_exit(c, 10);
    assert_eq!(code, 2, "an incomplete recv must exit 2");
}

#[test]
fn a_missing_input_file_exits_with_code_1() {
    let mut g = Guard::new();
    let missing = temp_path("a_missing_input_file_exits_with_code_1", "gone");
    let output = temp_path("a_missing_input_file_exits_with_code_1", "out");
    g.file(&output);
    let _ = std::fs::remove_file(&missing);
    let port = free_port();

    let r = g.spawn(&recv_args(port, &output, "5"));
    let s = g.spawn(&send_args(port, &missing, "2", "5"));

    let rc_send = g.wait_exit(s, 10);
    let rc_recv = g.wait_exit(r, 30);
    assert_eq!(rc_send, 1, "send with a missing --file must exit 1");
    assert!(!output.exists(), "the output file must not exist");
    assert_eq!(rc_recv, 1, "recv with no sender must exit 1");
}

#[test]
fn the_transfer_is_not_slow() {
    let mut g = Guard::new();
    let input = temp_path("the_transfer_is_not_slow", "in");
    let output = temp_path("the_transfer_is_not_slow", "out");
    g.file(&input);
    g.file(&output);
    let data = sample_data();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let start = Instant::now();
    let r = g.spawn(&recv_args(port, &output, "55"));
    let s = g.spawn(&send_args(port, &input, "2", "55"));

    let rc_send = g.wait_exit(s, 60);
    let rc_recv = g.wait_exit(r, 60);
    let elapsed = start.elapsed();
    let got = std::fs::read(&output).unwrap_or_default();
    assert_eq!(rc_send, 0, "send must exit 0");
    assert_eq!(rc_recv, 0, "recv must exit 0");
    assert_eq!(got, data, "the output file must equal the input file");
    assert!(
        elapsed < Duration::from_secs(20),
        "the 1,500,000-byte transfer took {elapsed:?}, over the 20 s limit"
    );
    eprintln!("transfer of 1,500,000 bytes took {elapsed:?}");
}

// The receiver checks its output path at startup, before binding: with no
// sender running at all, a path inside a directory that does not exist must
// fail within 3 seconds.
#[test]
fn an_unusable_output_path_fails_at_once() {
    let mut g = Guard::new();
    let missing_dir = temp_path("an_unusable_output_path_fails_at_once", "nodir");
    let output = missing_dir.join("out.bin");
    let part = part_path(&output);
    g.dir(&missing_dir);
    let _ = std::fs::remove_dir_all(&missing_dir);
    let port = free_port();

    let r = g.spawn_stderr(&recv_args(port, &output, "30"));
    let rc_recv = g.wait_exit(r, 3);
    let mut recv_err = String::new();
    g.children[r].stderr.as_mut().unwrap().read_to_string(&mut recv_err).unwrap();
    assert_eq!(rc_recv, 1, "recv with --out in a missing directory must exit 1");
    assert!(recv_err.contains("cannot write to"), "recv stderr must name the bad path, got: {recv_err}");
    assert!(!part.exists(), "the probe .part file must be removed again");
    assert!(!output.exists(), "the output file must not exist");
}

// The startup check passed, but the path turned into a directory while the
// transfer ran: the rename fails, the receiver reports 1 on stream 2, and
// the sender exits 1 with the file not stored.
#[test]
fn the_sender_fails_when_the_receiver_cannot_store_the_file() {
    let mut g = Guard::new();
    let input = temp_path("the_sender_fails_when_the_receiver_cannot_store_the_file", "in");
    let output = temp_path("the_sender_fails_when_the_receiver_cannot_store_the_file", "out");
    let part = part_path(&output);
    g.file(&input);
    g.file(&output);
    g.file(&part);
    g.dir(&output);
    let data: Vec<u8> = (0..50_000u64).map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8).collect();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let r = g.spawn_stderr(&recv_args(port, &output, "40"));
    // Let the receiver's startup check pass before blocking the rename.
    std::thread::sleep(Duration::from_millis(500));
    std::fs::create_dir_all(&output).unwrap();
    let s = g.spawn_stderr(&send_args(port, &input, "2", "40"));

    let rc_send = g.wait_exit(s, 60);
    let rc_recv = g.wait_exit(r, 60);
    let mut send_err = String::new();
    let mut recv_err = String::new();
    g.children[s].stderr.as_mut().unwrap().read_to_string(&mut send_err).unwrap();
    g.children[r].stderr.as_mut().unwrap().read_to_string(&mut recv_err).unwrap();
    assert_eq!(rc_send, 1, "send must exit 1 when the receiver cannot store the file");
    assert!(
        send_err.contains("receiver could not store the file"),
        "send stderr must report the store failure, got: {send_err}"
    );
    assert_eq!(rc_recv, 1, "recv must exit 1 when it cannot store the file");
    assert!(!part.exists(), "no .part file may be left");
}
