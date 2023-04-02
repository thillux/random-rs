use clap::Parser;
use std::ffi::CString;
use std::{thread};
use std::time::{Duration, Instant};
use std::sync::mpsc;
use std::arch::asm;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pkcs11_engine: String,
}

#[derive(Debug)]
enum Message {
    ReadRandom(String)
}

fn spawn_gather_thread_pkcs11(name: String, engine_path: String, tx: mpsc::Sender<Message>) {
    let engine_path_c =
        CString::new(engine_path).expect("Conversion to CString failed for opensc");

    thread::spawn(move || {
        let rand_buffer = [0; 256 / 8];

        let sc_ctx = unsafe {
            random_rs::sc_open(engine_path_c.into_raw())
        };

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

            let sleep_time = Duration::from_millis(1500);
            thread::sleep(sleep_time);
        }

        /*
        unsafe {
            random_rs::sc_close(sc_ctx);
        }
         */
    });
}

fn rdseed() -> u64 {
    let mut rand: u64 = 0;
    let one: u64 = 1;
    let mut valid: u64 = 0;
    while valid != 1 {
        unsafe {
            asm!(
            "RDSEED {rand}",
            "CMOVB {valid}, {one}",
            rand = out(reg) rand,
            one = in(reg) one,
            valid = out(reg) valid,
            );
        }
    }

    rand
}

fn spawn_gather_thread_rdrand(tx: mpsc::Sender<Message>) {
    thread::spawn(move || {
        loop {
            let mut rand_buffer = [0 as u8; 256 / 8];

            for chunk in rand_buffer.chunks_mut(8) {
                let rand = rdseed();
                chunk.clone_from_slice(&rand.to_le_bytes());
            }

            unsafe {
                random_rs::add_kernel_entropy(
                    0,
                    rand_buffer.as_ptr(),
                    rand_buffer.len(),
                )
            };

            tx.send(Message::ReadRandom(String::from("rdrand"))).unwrap();

            let sleep_time = Duration::from_millis(1500);
            thread::sleep(sleep_time);
        }
    });
}

fn main() {
    let args = Args::parse();

    let (tx, rx) = mpsc::channel();

    spawn_gather_thread_pkcs11(String::from("pkcs11"), args.pkcs11_engine, tx.clone());
    spawn_gather_thread_rdrand(tx.clone());

    for msg in rx {
        println!("{msg:?}");
    }
}
