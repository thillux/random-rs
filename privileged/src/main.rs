use common::SOCKET_PATH;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;

fn main() -> anyhow::Result<()> {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let unix_dgram = UnixDatagram::bind(common::SOCKET_PATH)?;
    let mut current_permission = std::fs::metadata(SOCKET_PATH)?.permissions();
    current_permission.set_mode(current_permission.mode() | 0o777);
    let _ = std::fs::set_permissions(SOCKET_PATH, current_permission);

    loop {
        let mut buffer = [0; 65535];
        println!("receive message");
        match unix_dgram.recv_from(&mut buffer) {
            Ok((size, _addr)) => {
                match bincode::decode_from_slice::<
                    common::EntropyMessage,
                    bincode::config::Configuration,
                >(&buffer[..size], bincode::config::standard())
                {
                    Ok((msg_decoded, _)) => {
                        println!("returned {msg_decoded:?}");
                    }
                    Err(_) => todo!(),
                }
            }
            Err(_) => todo!(),
        }
    }

    Ok(())
}
