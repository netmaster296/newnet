// The udpfile binary driven as two real processes over loopback UDP.

use std::net::UdpSocket;
use std::path::PathBuf;
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

// Wait for a child; kill it and fail the test past the time limit.
fn wait_exit(child: &mut Child, secs: u64) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => return status.code().unwrap_or(-1),
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not exit within {secs} s");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[test]
fn a_file_crosses_between_two_processes() {
    let input = temp_path("a_file_crosses_between_two_processes", "in");
    let output = temp_path("a_file_crosses_between_two_processes", "out");
    let data: Vec<u8> = (0..1_500_000u64)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8)
        .collect();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let mut recv = spawn(&[
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
        output.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        "55".into(),
    ]);
    let mut send = spawn(&[
        "send".into(),
        "--name".into(),
        "alice".into(),
        "--seed".into(),
        "1".into(),
        "--peer".into(),
        "bob".into(),
        "--peer-seed".into(),
        "2".into(),
        "--to".into(),
        format!("127.0.0.1:{port}"),
        "--file".into(),
        input.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        "55".into(),
    ]);

    let rc_send = wait_exit(&mut send, 60);
    let rc_recv = wait_exit(&mut recv, 60);
    let got = std::fs::read(&output).unwrap_or_default();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_eq!(rc_send, 0, "send must exit 0");
    assert_eq!(rc_recv, 0, "recv must exit 0");
    assert_eq!(got, data, "the output file must equal the input file");
}

#[test]
fn a_wrong_peer_key_transfers_nothing() {
    let input = temp_path("a_wrong_peer_key_transfers_nothing", "in");
    let output = temp_path("a_wrong_peer_key_transfers_nothing", "out");
    let data: Vec<u8> = (0..1_500_000u64)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i / 1000)) as u8)
        .collect();
    std::fs::write(&input, &data).unwrap();
    let port = free_port();

    let mut recv = spawn(&[
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
        output.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        "3".into(),
    ]);
    let mut send = spawn(&[
        "send".into(),
        "--name".into(),
        "alice".into(),
        "--seed".into(),
        "1".into(),
        "--peer".into(),
        "bob".into(),
        "--peer-seed".into(),
        "999".into(),
        "--to".into(),
        format!("127.0.0.1:{port}"),
        "--file".into(),
        input.to_string_lossy().into_owned(),
        "--timeout-secs".into(),
        "3".into(),
    ]);

    let rc_send = wait_exit(&mut send, 30);
    let rc_recv = wait_exit(&mut recv, 30);
    let existed = output.exists();
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    assert_eq!(rc_send, 1, "send with a wrong peer key must exit 1");
    assert_eq!(rc_recv, 1, "recv must exit 1");
    assert!(!existed, "the output file must not exist");
}

#[test]
fn bad_arguments_exit_with_code_2() {
    let mut child = udpfile().args(["recv", "--name", "bob"]).spawn().unwrap();
    let code = wait_exit(&mut child, 10);
    assert_eq!(code, 2, "an incomplete recv must exit 2");
}
