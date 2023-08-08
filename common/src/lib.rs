use std::ffi::{c_int, CStr};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

pub const SOCKET_PATH: &str = "/var/run/random-server.sock";

static mut registered_serials: Mutex<Vec<String>> = Mutex::new(vec![]);

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub enum EntropySourceType {
    Pkcs11,
    Gpg,
    Rdseed,
    Hwrng,
    Jitterentropy,
    Sound,
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
pub struct EntropyMessage {
    pub source: EntropySourceType,
    pub random_bytes: Vec<u8>,
    pub entropy_bits: u32,
}

extern "C" {
    pub fn get_kernel_entropy() -> u32;
    pub fn add_kernel_entropy(ent_count: i32, buffer: *const u8, size: usize);
    pub fn add_kernel_entropy_unaccounted(buffer: *const u8, size: usize);
    pub fn reseed();

    pub fn sc_open(s: *const c_char) -> *mut c_void;
    pub fn sc_random(ctx: *mut c_void, buffer: *const u8, size: usize);
    pub fn sc_close(ctx: *mut c_void);

    pub fn sc_login(ctx: *mut c_void, so: c_int, pin: *const c_char) -> c_int;
    pub fn sc_logout(ctx: *mut c_void) -> c_int;

    pub fn jent_open(osr: u32) -> *mut c_void;
    pub fn jent_random(ctx: *mut c_void, buffer: *const u8, size: usize);
    pub fn jent_close(ctx: *mut c_void);

    pub fn scd_open() -> *mut c_void;
    pub fn scd_random(ctx: *mut c_void, buffer: *const u8, size: usize) -> bool;
    pub fn scd_refresh_cards(ctx: *mut c_void);
    pub fn scd_list_cards(ctx: *mut c_void);
    pub fn scd_select_card(ctx: *mut c_void, serialno: *const c_char);
    pub fn scd_close(ctx: *mut c_void);
}

#[no_mangle]
pub extern "C" fn scd_report_serialno(serialno: *const c_char) {
    let r_serial = unsafe {
        CStr::from_ptr(serialno)
    };
    let s = r_serial.to_string_lossy().into_owned();
    unsafe {
        registered_serials.lock().unwrap().push(s);
    }
}

pub fn scd_get_cards() -> Vec<String> {
    let v = unsafe {
        registered_serials.lock().unwrap().clone()
    };
    return v;
}

pub fn add_entropy(buf: &[u8; 256]) {
    unsafe {
        add_kernel_entropy(
            i32::try_from(buf.len() * 8).unwrap(),
            buf.as_ptr(),
            buf.len(),
        );
    }
}
