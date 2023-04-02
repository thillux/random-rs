use std::ffi::CString;
use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pkcs11_engine: String,
}

fn main() {
    let args = Args::parse();

    let opensc_engine_path = CString::new(args.pkcs11_engine).expect("Conversion to CString failed");

    let mut rand_buffer = [0; 4];
    unsafe {
        let ctx = random_rs::sc_open(opensc_engine_path.into_raw());
        for i in 0..100 {
            random_rs::sc_random(ctx, rand_buffer.as_ptr(), rand_buffer.len());
            println!("{rand_buffer:x?}");
            random_rs::add_kernel_entropy(i32::try_from(rand_buffer.len() * 8).unwrap(), rand_buffer.as_ptr(), rand_buffer.len());
        }
        random_rs::sc_close(ctx);
    }
}
