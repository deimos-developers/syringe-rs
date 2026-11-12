//! Hook/host section parsing and handshake handling.

use std::ffi::{CString, c_void};
use std::io::Read;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

use crate::handle::ModuleHandle;
use crate::log_line;
use crate::portable_executable::PortableExecutable;
use crate::syringe_api::{HookDecl, HostDecl, SyringeHandshakeInfo};

use super::{HookBuffer, SyringeDebugger, parse_hex_prefix};

impl SyringeDebugger {
    pub(super) fn parse_inj_file_hooks(lib: &str, hooks: &mut HookBuffer) -> bool {
        let inj = format!("{}.inj", lib);
        let Ok(mut file) = std::fs::File::open(inj) else {
            return false;
        };

        const SIZE: usize = 0x100;
        let mut line = [0u8; SIZE];

        loop {
            let mut length = 0;

            while length < SIZE - 1 {
                let mut byte = [0u8; 1];
                match file.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        line[length] = byte[0];
                        length += 1;
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                }
            }

            if length == 0 {
                break;
            }

            let first = line[0];
            if first == b';' || first == b'\r' || first == b'\n' {
                continue;
            }

            let text = String::from_utf8_lossy(&line[..length]);
            let Some((address_part, rest)) = text.split_once('=') else {
                continue;
            };

            let address = address_part.trim();
            let address = address
                .strip_prefix("0x")
                .or_else(|| address.strip_prefix("0X"))
                .unwrap_or(address);
            let Ok(eip) = u32::from_str_radix(address, 16) else {
                continue;
            };

            let (function_part, override_part) = rest.split_once(',').unwrap_or((rest, ""));
            let function = function_part
                .trim_start()
                .split(|c: char| {
                    c == ' ' || c == '\t' || c == ';' || c == ',' || c == '\r' || c == '\n'
                })
                .next()
                .unwrap_or("");

            if function.is_empty() {
                continue;
            }

            let overridden_text = override_part.trim();
            let overridden = parse_hex_prefix(overridden_text).unwrap_or(0);
            hooks.add_named(
                eip as usize as *mut c_void,
                lib,
                function,
                overridden as usize,
            );
        }

        true
    }

    pub(super) fn can_host_dll(
        &self,
        dll: &mut PortableExecutable,
        hosts: &IMAGE_SECTION_HEADER,
    ) -> bool {
        const SIZE: u32 = size_of::<HostDecl>() as u32;

        let base = dll.image_base();
        let begin = hosts.PointerToRawData;
        let end = begin.wrapping_add(hosts.SizeOfRawData);

        let mut pointer = begin;
        while pointer < end {
            let mut bytes = [0u8; size_of::<HostDecl>()];
            if !dll.read_bytes(pointer, SIZE as usize, &mut bytes) {
                break;
            }

            let host_decl: HostDecl =
                unsafe { ptr::read_unaligned(bytes.as_ptr() as *const HostDecl) };

            if host_decl.host_name_ptr != 0 {
                let raw_name_ptr = dll.virtual_to_raw(host_decl.host_name_ptr.wrapping_sub(base));

                if let Some(mut host_name) = dll.read_c_string(raw_name_ptr) {
                    host_name.push_str(".exe");

                    let host_file = std::path::Path::new(&self.exe)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or(&self.exe);
                    if host_name.eq_ignore_ascii_case(host_file) {
                        return true;
                    }
                }
            }

            pointer = pointer.wrapping_add(SIZE);
        }

        false
    }

    pub(super) fn parse_hooks_section(
        &self,
        dll: &mut PortableExecutable,
        hooks: &IMAGE_SECTION_HEADER,
        buffer: &mut HookBuffer,
    ) -> bool {
        const SIZE: u32 = size_of::<HookDecl>() as u32;

        let base = dll.image_base();
        let filename = dll.filename().to_string();
        let begin = hooks.PointerToRawData;
        let end = begin.wrapping_add(hooks.SizeOfRawData);

        let mut pointer = begin;
        while pointer < end {
            if end - pointer < SIZE {
                // A short trailing record is section padding, not a hook.
                break;
            }
            let mut bytes = [0u8; size_of::<HookDecl>()];
            if !dll.read_bytes(pointer, SIZE as usize, &mut bytes) {
                log_line!("parse_hooks_section", "bytes read failed");
                return false;
            }

            let hook_decl: HookDecl =
                unsafe { ptr::read_unaligned(bytes.as_ptr() as *const HookDecl) };

            if hook_decl.hook_name_ptr != 0 {
                let raw_name_ptr = dll.virtual_to_raw(hook_decl.hook_name_ptr.wrapping_sub(base));

                if let Some(hook_name) = dll.read_c_string(raw_name_ptr) {
                    buffer.add_named(
                        hook_decl.hook_addr as usize as *mut c_void,
                        &filename,
                        &hook_name,
                        hook_decl.hook_size as usize,
                    );
                }
            }

            pointer = pointer.wrapping_add(SIZE);
        }

        true
    }

    pub(super) fn handshake(&self, lib: &str, hooks: i32, crc: u32) -> Option<bool> {
        if !self.b_handshakes {
            log_line!("handshake", "Skipping handshake for DLL: \"{}\"", lib);
            return None;
        }

        let Ok(library_name) = CString::new(lib.as_bytes()) else {
            log_line!("handshake", "Skipping DLL with an embedded NUL: {:?}", lib);
            return None;
        };
        let module = unsafe { LoadLibraryA(library_name.as_ptr() as *const u8) };
        let module = ModuleHandle::new(module);

        if !module.is_valid() {
            return None;
        }

        let proc = unsafe { GetProcAddress(module.get(), b"SyringeHandshake\0".as_ptr()) };

        let Some(proc) = proc else {
            return None;
        };

        let func: unsafe extern "C" fn(*mut SyringeHandshakeInfo) -> i32 =
            unsafe { std::mem::transmute(proc) };

        log_line!("handshake", "Calling \"{}\" ...", lib);

        const SIZE: usize = 0x100;
        let mut buffer = vec![0u8; SIZE + 1];
        let mut info = SyringeHandshakeInfo {
            cb_size: size_of::<SyringeHandshakeInfo>() as i32,
            num_hooks: hooks,
            checksum: crc,
            exe_filesize: self.dw_exe_size,
            exe_timestamp: self.dw_time_stamp,
            exe_crc: self.dw_exe_crc,
            cch_message: SIZE as i32,
            message: buffer.as_mut_ptr() as *mut i8,
        };

        let result = unsafe { func(&mut info) };

        if result >= 0 {
            buffer[SIZE] = 0;
            let length = buffer.iter().position(|&value| value == 0).unwrap_or(SIZE);
            let answer = String::from_utf8_lossy(&buffer[..length]);

            log_line!("handshake", "Answers \"{}\" ({:X})", answer, result);
            Some(result == 0)
        } else {
            log_line!("handshake", "Failed ({:X})", result);
            Some(false)
        }
    }
}
