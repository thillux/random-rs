use clap::Parser;
use common::{jent_close, jent_random};
use common::{EntropyMessage, EntropySourceType};
use std::arch::asm;
use std::ffi::CString;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pkcs11_engine: String,
}

fn spawn_gather_thread_gpg(tx: mpsc::Sender<EntropyMessage>) {
    thread::spawn(move || {
        let ctx = unsafe {
            common::scd_open()
        };
        unsafe {
            common::scd_refresh_cards(ctx);
            common::scd_list_cards(ctx);
        }
        loop {
            for serialno in common::scd_get_cards() {
                unsafe {
                    let cs = CString::new(serialno).unwrap();
                    common::scd_select_card(ctx, cs.as_ptr());
                }
                for _i in 1..32 {
                    let mut msg = EntropyMessage {
                        source: EntropySourceType::Gpg,
                        random_bytes: vec![],
                        entropy_bits: 0,
                    };
                    msg.random_bytes.resize(32, 0);
                    let valid =
                        unsafe { common::scd_random(ctx, msg.random_bytes.as_ptr(), msg.random_bytes.len()) };

                    if valid {
                        msg.entropy_bits = u32::try_from(msg.random_bytes.len() * 8).unwrap();
                        tx.send(msg).unwrap();
                    }
                }
            }

            let sleep_time = Duration::from_millis(10 * 1000);
            thread::sleep(sleep_time);
        }

        unsafe {
            common::scd_close(ctx);
        }
    });
}

fn cpuid(fun: u32) -> (u32, u32, u32, u32) {
    let (mut a, mut b, mut c, mut d) = (0, 0, 0, 0);

    unsafe {
        asm!("PUSH rbx",
        "CPUID",
        "MOV {b:e}, ebx",
        "POP rbx",
        b = out(reg) b,
        lateout("eax") a,
        lateout("ecx") c,
        lateout("edx") d,
        in("eax") fun,
        );
    };

    (a, b, c, d)
}

fn rdrand64_step(has_rdseed: bool, has_rdrand: bool) -> Option<u64> {
    let mut rand: u64;
    let mut valid: u8;

    if has_rdseed {
        unsafe {
            asm!(
            "RDSEED {rand:r}",
            "SETC {valid}",
            rand = out(reg) rand,
            valid = out(reg_byte) valid,
            );
        };
    } else if has_rdrand {
        unsafe {
            asm!(
            "RDRAND {rand:r}",
            "SETC {valid}",
            rand = out(reg) rand,
            valid = out(reg_byte) valid,
            );
        };
    } else {
        panic!("Called rdrand_step with CPU support for rdrand and rdseed");
    }

    if valid == 1 {
        Some(rand)
    } else {
        None
    }
}

fn rdseed() -> u64 {
    let (_, _, ecx, _) = cpuid(0x1);
    let has_rdrand = (ecx & (1 << 30)) > 0;
    let (_, ebx, _, _) = cpuid(0x7);
    let has_rdseed = (ebx & (1 << 18)) > 0;

    // println!("CPU random support is rdseed = {has_rdseed}, rdrand = {has_rdrand}");

    let mut rand = None;
    while rand.is_none() {
        rand = rdrand64_step(has_rdseed, has_rdrand);
    }

    rand.unwrap()
}

fn spawn_gather_thread_rdrand(tx: mpsc::Sender<EntropyMessage>) {
    thread::spawn(move || loop {
        let mut msg = EntropyMessage {
            source: EntropySourceType::Rdseed,
            random_bytes: vec![],
            entropy_bits: 0,
        };
        msg.random_bytes.resize(32, 0);
        for chunk in msg.random_bytes.chunks_mut(8) {
            let rand = rdseed();
            chunk.clone_from_slice(&rand.to_le_bytes());
        }
        msg.entropy_bits = u32::try_from(msg.random_bytes.len() * 8).unwrap();
        tx.send(msg).unwrap();

        let sleep_time = Duration::from_millis(10 * 1000);
        thread::sleep(sleep_time);
    });
}

fn spawn_gather_thread_jent(tx: mpsc::Sender<EntropyMessage>) {
    thread::spawn(move || {
        let jent_ctx = unsafe { common::jent_open(10) };

        loop {
            let mut msg = EntropyMessage {
                source: EntropySourceType::Jitterentropy,
                random_bytes: vec![],
                entropy_bits: 0,
            };

            msg.random_bytes.resize(32, 0);
            unsafe {
                jent_random(jent_ctx, msg.random_bytes.as_ptr(), msg.random_bytes.len());
            };

            msg.entropy_bits = u32::try_from(msg.random_bytes.len() * 8).unwrap();
            tx.send(msg).unwrap();

            let sleep_time = Duration::from_millis(10 * 1000);
            thread::sleep(sleep_time);
        }
        unsafe {
            jent_close(jent_ctx);
        };
    });
}

fn main() -> anyhow::Result<()> {
    //let args = Args::parse();

    let (tx, rx) = mpsc::channel();

    spawn_gather_thread_gpg(tx.clone());
    spawn_gather_thread_jent(tx.clone());
    spawn_gather_thread_rdrand(tx);

    let unix_dgram = UnixDatagram::unbound()?;
    for msg in rx {
        let buffer: Vec<u8> = bincode::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        let _ = unix_dgram.send_to(&buffer, Path::new(common::SOCKET_PATH));
    }

    Ok(())
}

#[test]
fn rdseed_step_stress() {
    for _i in 0..1_000_000 {
        assert!(rdrand64_step(false, true).is_some());
    }
}
