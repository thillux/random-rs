use std::ffi::c_int;
use std::os::raw::{c_char, c_void};

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

    pub fn scd_random(buffer: *const u8, size: usize) -> bool;
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
