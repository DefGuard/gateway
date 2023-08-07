use std::{
    alloc::{alloc, dealloc, Layout},
    error::Error,
    fmt,
    ptr::null_mut,
    slice::from_raw_parts,
};

#[derive(Debug)]
pub enum WgIoError {
    MemAlloc,
}

impl Error for WgIoError {}

impl fmt::Display for WgIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemAlloc => write!(f, "memory allocation"),
        }
    }
}

/// Represent `struct wg_data_io` defined in
/// https://github.com/freebsd/freebsd-src/blob/main/sys/dev/wg/if_wg.h
#[repr(C)]
pub struct WgDataIo {
    pub(super) wgd_name: [u8; 16],
    pub(super) wgd_data: *mut u8, // *void
    pub(super) wgd_size: usize,
}

impl WgDataIo {
    /// Create `WgDataIo` without data buffer.
    #[must_use]
    pub fn new(if_name: &str) -> Self {
        let mut wgd_name = [0u8; 16];
        if_name
            .bytes()
            .take(15)
            .enumerate()
            .for_each(|(i, b)| wgd_name[i] = b);
        Self {
            wgd_name,
            wgd_data: null_mut(),
            wgd_size: 0,
        }
    }

    /// Allocate data buffer.
    pub fn alloc_data(&mut self) -> Result<(), WgIoError> {
        if self.wgd_data.is_null() {
            if let Ok(layout) = Layout::array::<u8>(self.wgd_size) {
                unsafe {
                    self.wgd_data = alloc(layout);
                }
                return Ok(());
            }
        }
        Err(WgIoError::MemAlloc)
    }

    pub fn as_buf<'a>(&self) -> &'a [u8] {
        unsafe { from_raw_parts(self.wgd_data, self.wgd_size) }
    }
}

impl Drop for WgDataIo {
    fn drop(&mut self) {
        eprintln!("Dropping WgDataIo");
        if self.wgd_size != 0 {
            let layout = Layout::array::<u8>(self.wgd_size).expect("Bad layout");
            unsafe {
                dealloc(self.wgd_data, layout);
            }
        }
    }
}
