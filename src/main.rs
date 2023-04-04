use clap::Parser;
use std::arch::asm;
use std::ffi::CString;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pkcs11_engine: String,
}

#[derive(Debug)]
enum EntropySourceType {
    Pkcs11,
    Rdseed,
}

#[derive(Debug)]
enum Message {
    Initialized(EntropySourceType),
    ReadRandom(String),
}

fn spawn_gather_thread_pkcs11(name: String, engine_path: String, tx: mpsc::Sender<Message>) {
    let engine_path_c = CString::new(engine_path).expect("Conversion to CString failed for opensc");

    thread::spawn(move || {
        let rand_buffer = [0; 256 / 8];

        let sc_ctx = unsafe { random_rs::sc_open(engine_path_c.into_raw()) };

        tx.send(Message::Initialized(EntropySourceType::Pkcs11))
            .unwrap();

        loop {
            unsafe {
                random_rs::sc_random(sc_ctx, rand_buffer.as_ptr(), rand_buffer.len());
            };
            // println!("{rand_buffer:x?}");
            unsafe {
                random_rs::add_kernel_entropy(
                    i32::try_from(rand_buffer.len() * 8).unwrap(),
                    rand_buffer.as_ptr(),
                    rand_buffer.len(),
                )
            };

            tx.send(Message::ReadRandom(name.clone())).unwrap();

            let sleep_time = Duration::from_millis(10 * 1000);
            thread::sleep(sleep_time);
        }

        /*
        unsafe {
            random_rs::sc_close(sc_ctx);
        }
         */
    });
}

fn rdseed64_step() -> Option<u64> {
    let mut rand: u64;
    let one: u64 = 1;
    let zero: u64 = 0;
    let mut valid: u64;

    unsafe {
        asm!(
        "RDRAND {rand}",
        "CMOVB {valid}, {one}",
        "CMOVNB {valid}, {zero}",
        rand = out(reg) rand,
        one = in(reg) one,
        zero = in(reg) zero,
        valid = out(reg) valid,
        );
    }

    if valid == 1 {
        Some(rand)
    } else {
        None
    }
}

fn rdseed() -> u64 {
    let mut rand= None;
    while rand.is_none() {
        rand = rdseed64_step();
    }

    rand.unwrap()
}

fn spawn_gather_thread_rdrand(tx: mpsc::Sender<Message>) {
    thread::spawn(move || {
        tx.send(Message::Initialized(EntropySourceType::Rdseed))
            .unwrap();

        loop {
            let mut rand_buffer = [0_u8; 256 / 8];

            for chunk in rand_buffer.chunks_mut(8) {
                let rand = rdseed();
                chunk.clone_from_slice(&rand.to_le_bytes());
            }

            unsafe { random_rs::add_kernel_entropy(0, rand_buffer.as_ptr(), rand_buffer.len()) };

            tx.send(Message::ReadRandom(String::from("rdrand")))
                .unwrap();

            let sleep_time = Duration::from_millis(10 * 1000);
            thread::sleep(sleep_time);
        }
    });
}

fn main() {
    let args = Args::parse();

    let (tx, rx) = mpsc::channel();

    spawn_gather_thread_pkcs11(String::from("pkcs11"), args.pkcs11_engine, tx.clone());
    spawn_gather_thread_rdrand(tx);

    for msg in rx {
        println!("{msg:?}");
    }
}

#[test]
fn rdseed_step_stress() {
    for _i in 0 .. 1_000_000 {
        assert!(rdseed64_step().is_some());
    }
}