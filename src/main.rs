use clap::Parser;
use std::ffi::CString;
use std::{thread, time};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pkcs11_engine_sc: String,

    #[arg(short, long)]
    pkcs11_engine_tpm2: String,
}

fn main() {
    let args = Args::parse();

    let opensc_engine_path =
        CString::new(args.pkcs11_engine_sc).expect("Conversion to CString failed for opensc");
    let tpm2_engine_path = CString::new(args.pkcs11_engine_tpm2)
        .expect("Conversion to CString failed for tpm2 engine");

    let rand_buffer = [0; 256 / 8];
    unsafe {
        let sc_ctx = random_rs::sc_open(opensc_engine_path.into_raw());
        let tpm2_ctx = random_rs::sc_open(tpm2_engine_path.into_raw());
        loop {
            random_rs::sc_random(sc_ctx, rand_buffer.as_ptr(), rand_buffer.len());
            println!("{rand_buffer:x?}");
            random_rs::add_kernel_entropy(
                i32::try_from(rand_buffer.len() * 8).unwrap(),
                rand_buffer.as_ptr(),
                rand_buffer.len(),
            );

            random_rs::sc_random(tpm2_ctx, rand_buffer.as_ptr(), rand_buffer.len());
            println!("{rand_buffer:x?}");
            random_rs::add_kernel_entropy(
                i32::try_from(0).unwrap(),
                rand_buffer.as_ptr(),
                rand_buffer.len(),
            );

            let sleep_time = time::Duration::from_millis(1500);
            thread::sleep(sleep_time);
        }
        random_rs::sc_close(sc_ctx);
        random_rs::sc_close(tpm2_ctx);
    }
}
