// The udpfile binary driven as two real processes over loopback UDP.

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
}

impl Guard {
    fn new() -> Guard {
        Guard { children: Vec::new(), files: Vec::new() }
    }

    fn spawn(&mut self, args: &[String]) -> usize {
        self.children.push(spawn(args));
        self.children.len() - 1
    }

    fn file(&mut self, p: &Path) {
        self.files.push(p.to_path_buf());
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

    let r = g.spawn(&recv_args(port, &output, "3"));
    let s = g.spawn(&send_args(port, &input, "999", "3"));

    let rc_send = g.wait_exit(s, 30);
    let rc_recv = g.wait_exit(r, 30);
    let existed = output.exists();
    assert_eq!(rc_send, 1, "send with a wrong peer key must exit 1");
    assert_eq!(rc_recv, 1, "recv must exit 1");
    assert!(!existed, "the output file must not exist");
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
