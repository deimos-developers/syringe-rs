//! Translation of `SyringeEx/Log.h` and `SyringeEx/Log.cpp`.
//!
//! The original uses C variadic formatting and `localtime_s`. The Rust port
//! keeps the same public API shape (`open`, `write_line`, `flush`) and the same
//! output layout, but takes its arguments through `format_args!`.

use std::ffi::c_void;
use std::fmt::Arguments;
use std::mem::zeroed;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

use crate::handle::FileHandle;

static LOG: Mutex<Option<LogState>> = Mutex::new(None);

struct LogState {
    file: FileHandle,
}

// `_fsopen` and the stdio entry points live in the CRT rather than in
// windows-sys. The declarations mirror <stdio.h>.
unsafe extern "C" {
    fn _fsopen(filename: *const i8, mode: *const i8, shflag: i32) -> *mut c_void;
    fn fflush(file: *mut c_void) -> i32;
    fn fwrite(
        buffer: *const c_void,
        element_size: usize,
        element_count: usize,
        file: *mut c_void,
    ) -> usize;
}

const SH_DENYWR: i32 = 0x20;

pub struct Log;

impl Log {
    pub fn open(filename: &str) -> bool {
        if filename.is_empty() {
            return Self::is_open();
        }

        let mut name = filename.as_bytes().to_vec();
        name.push(0);

        let file = unsafe {
            _fsopen(
                name.as_ptr() as *const i8,
                b"w\0".as_ptr() as *const i8,
                SH_DENYWR,
            )
        };
        let mut guard = LOG.lock().unwrap();
        *guard = Some(LogState {
            file: FileHandle::new(file),
        });

        !file.is_null()
    }

    pub fn is_open() -> bool {
        LOG.lock()
            .unwrap()
            .as_ref()
            .is_some_and(|state| state.file.is_valid())
    }

    pub fn flush() {
        let guard = LOG.lock().unwrap();
        if let Some(state) = guard.as_ref() {
            if state.file.is_valid() {
                unsafe { fflush(state.file.get()) };
            }
        }
    }

    fn timestamp_string() -> String {
        let mut time: SYSTEMTIME = unsafe { zeroed() };
        unsafe { GetLocalTime(&mut time) };

        format!(
            "[{:02}:{:02}:{:02}:{:03}] ",
            time.wHour, time.wMinute, time.wSecond, time.wMilliseconds
        )
    }

    fn write_bytes(file: *mut c_void, bytes: &[u8]) {
        if !bytes.is_empty() {
            unsafe {
                fwrite(bytes.as_ptr() as *const c_void, 1, bytes.len(), file);
            }
        }
    }

    pub fn write_line_args(args: Arguments<'_>) {
        let text = args.to_string();
        let timestamp = Self::timestamp_string();

        let guard = LOG.lock().unwrap();
        let Some(state) = guard.as_ref() else {
            return;
        };

        if !state.file.is_valid() {
            return;
        }

        Self::write_bytes(state.file.get(), timestamp.as_bytes());
        Self::write_bytes(state.file.get(), text.as_bytes());
        Self::write_bytes(state.file.get(), b"\n");
        unsafe { fflush(state.file.get()) };
    }

    pub fn write_line() {
        let guard = LOG.lock().unwrap();
        let Some(state) = guard.as_ref() else {
            return;
        };

        if state.file.is_valid() {
            Self::write_bytes(state.file.get(), b"\n");
        }
    }

    pub fn write_line_fmt(args: Arguments<'_>) {
        Self::write_line_args(args);
    }
}

#[macro_export]
macro_rules! log_line {
    () => {
        $crate::log::Log::write_line()
    };
    ($function:literal, $($arg:tt)*) => {
        $crate::log::Log::write_line_args(format_args!(
            "Debug: {}: {}",
            $function,
            format_args!($($arg)*)
        ))
    };
}
