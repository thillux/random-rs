use common::SOCKET_PATH;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;

use sha3::digest::Update;
use sha3::Shake256;

fn main() -> anyhow::Result<()> {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let unix_dgram = UnixDatagram::bind(common::SOCKET_PATH)?;
    let mut current_permission = std::fs::metadata(SOCKET_PATH)?.permissions();
    current_permission.set_mode(current_permission.mode() | 0o777);
    let _ = std::fs::set_permissions(SOCKET_PATH, current_permission);

    let mut hasher = Shake256::default();
    let mut entropy_bits: u32 = 0;

    // spawn_gather_thread_hwrng(tx.clone());

    loop {
        let mut buffer = [0; 65535];
        match unix_dgram.recv_from(&mut buffer) {
            Ok((size, _addr)) => {
                match bincode::decode_from_slice::<
                    common::EntropyMessage,
                    bincode::config::Configuration,
                >(&buffer[..size], bincode::config::standard())
                {
                    Ok((msg_decoded, _)) => {
                        hasher.update(&msg_decoded.random_bytes);
                        entropy_bits += msg_decoded.entropy_bits;
                        let bits = msg_decoded.entropy_bits;
                        println!("added {bits} bits to pool!");
                    }
                    Err(_) => todo!(),
                }
            }
            Err(_) => todo!(),
        }
    }

    Ok(())
}
