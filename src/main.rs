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
                );
                random_rs::reseed();
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

fn cpuid(fun: u32) -> (u32, u32, u32, u32) {
    let (mut a, mut b, mut c, mut d) = (0,0,0,0);

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
    }
    else {
        panic!("Called rdrand_step with CPU support for rdrand and rdseed");
    }

    if valid == 1 {
        Some(rand)
    } else {
        None
    }
}

fn rdseed() -> u64 {
    let (mut eax, mut ebx, mut ecx, mut edx) = cpuid(0x1);
    let has_rdrand = (ecx & (1 << 30)) > 0;
    (eax, ebx, ecx, edx) = cpuid(0x7);
    let has_rdseed = (ebx & (1 << 18)) > 0;

    // println!("CPU random support is rdseed = {has_rdseed}, rdrand = {has_rdrand}");

    let mut rand= None;
    while rand.is_none() {
        rand = rdrand64_step(has_rdseed, has_rdrand);
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
            // println!("{rand_buffer:x?}");

            unsafe {
                random_rs::add_kernel_entropy(0, rand_buffer.as_ptr(), rand_buffer.len());
                random_rs::reseed();
            };

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
        assert!(rdrand64_step(false, true).is_some());
    }
}