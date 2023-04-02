use std::os::raw::{c_void, c_char};

extern "C" {
    pub fn get_kernel_entropy() -> u32;
    pub fn add_kernel_entropy(ent_count: i32, buffer: *const u8, size: usize);
    pub fn sc_open(s: *const c_char) -> *mut c_void;
    pub fn sc_random(ctx: *mut c_void, buffer: *const u8, size: usize);
    pub fn sc_close(ctx: *mut c_void);
}

pub fn add_entropy(buf: &[u8; 256]) {
    unsafe {
        add_kernel_entropy(i32::try_from(buf.len() * 8).unwrap(), buf.as_ptr(), buf.len());
    }
}
