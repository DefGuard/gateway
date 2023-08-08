use std::{
    mem::size_of,
    time::{Duration, SystemTime},
};

use super::cast_ref;

#[repr(C)]
struct TimeSpec64 {
    tv_sec: u64,  // i64
    tv_nsec: u64, // i64
}

impl From<&TimeSpec64> for SystemTime {
    fn from(ts: &TimeSpec64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(ts.tv_sec) + Duration::from_nanos(ts.tv_nsec)
    }
}

pub(super) fn unpack_timespec(buf: &[u8]) -> Option<SystemTime> {
    const TS_SIZE: usize = size_of::<TimeSpec64>();
    match buf.len() {
        TS_SIZE => {
            let ts = unsafe { cast_ref::<TimeSpec64>(buf) };
            Some(ts.into())
        }
        _ => None,
    }
}
