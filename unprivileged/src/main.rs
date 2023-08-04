use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::thread;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let unix_dgram = UnixDatagram::unbound()?;
    loop {
        let mut msg = common::EntropyMessage {
            source: String::from("me"),
            random_bytes: vec![],
            entropy_bits: 0,
        };
        msg.random_bytes.resize(32, 0);
        let valid =
            unsafe { common::scd_random(msg.random_bytes.as_ptr(), msg.random_bytes.len()) };

        if valid {
            let buffer: Vec<u8> =
                bincode::encode_to_vec(&msg, bincode::config::standard()).unwrap();
            let _ = unix_dgram.send_to(&buffer, Path::new(common::SOCKET_PATH));
        }

        let sleep_time = Duration::from_millis(10 * 1000);
        thread::sleep(sleep_time);
    }
}
