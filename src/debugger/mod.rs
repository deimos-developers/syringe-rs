//! Translation of `SyringeEx/SyringeDebugger.h` and `SyringeDebugger.cpp`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CString, c_void};
use std::mem::{size_of, zeroed};
use std::ptr;

use crate::handle::{ThreadHandle, VirtualMemoryHandle};
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_EXCEPTION_NOT_HANDLED, ERROR_ARITHMETIC_OVERFLOW, ERROR_ERRORS_ENCOUNTERED,
    ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ENOUGH_MEMORY, ERROR_PROC_NOT_FOUND, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, GetLastError, HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_X86, CONTEXT_FULL_X86, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    FlushInstructionCache, GetThreadContext, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS32,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
    ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
};
use windows_sys::Win32::System::Environment::SetEnvironmentVariableA;
use windows_sys::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, VirtualQueryEx,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessA, DEBUG_ONLY_THIS_PROCESS, GetExitCodeProcess, INFINITE,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOA, WaitForSingleObject,
};
use zydis::{
    AllOperands, BranchType, BranchWidth, Decoder, EncoderRequest, InstructionAttributes,
    InstructionCategory, Mnemonic, OperandType, ffi,
};

use crate::crc32::Crc32;
use crate::find_file::FindFile;

use crate::log_line;
use crate::portable_executable::PortableExecutable;
use crate::support::{LastError, throw_lasterror, throw_lasterror_or};
use crate::syringe_api::FEATURE_FLAGS;

mod discovery;

const MAX_NAME_LENGTH: usize = 0x100;
const INT3: u8 = 0xCC;
const NOP: u8 = 0x90;
const MAX_PATCH_GAP: usize = 0x1000;

const INCLUDE_FLAG: &str = "-i=";
const DETACH_FLAG: &str = "--detach";
const NODETACH_FLAG: &str = "--nodetach";
const NOWAIT_FLAG: &str = "--nowait";
const HANDSHAKES_FLAG: &str = "--handshakes";

const CODE_CALL: [u8; 73] = [
    0x60, 0x9C, 0x68, 0x00, 0x00, 0x00, 0x00, 0x54, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x08,
    0x64, 0xA3, 0x14, 0x00, 0x00, 0x00, 0x64, 0x83, 0x3D, 0x14, 0x00, 0x00, 0x00, 0x00, 0x74, 0x18,
    0x9D, 0x5F, 0x5E, 0x5D, 0x5B, 0x8B, 0x44, 0x24, 0x0C, 0x89, 0x5C, 0x24, 0x0C, 0x5B, 0x5A, 0x59,
    0x5C, 0x64, 0xFF, 0x25, 0x14, 0x00, 0x00, 0x00, 0x9D, 0x5F, 0x5E, 0x5D, 0x5B, 0x8B, 0x44, 0x24,
    0x0C, 0x89, 0x5C, 0x24, 0x0C, 0x5B, 0x5A, 0x59, 0x5C,
];

const JMP_BACK: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];
const JMP: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];

const C_LOAD_LIBRARY: [u8; 45] = [
    0x50, 0x51, 0x52, 0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xA3, 0x00,
    0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x0C, 0x68, 0x00, 0x00, 0x00, 0x00, 0x50, 0xFF, 0x15, 0x00,
    0x00, 0x00, 0x00, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x5A, 0x59, 0x58, 0xCC, 0x90,
];

#[derive(Clone)]
struct Hook {
    lib: [u8; MAX_NAME_LENGTH],
    proc: [u8; MAX_NAME_LENGTH],
    proc_address: *mut c_void,
    num_overridden: usize,
}

impl Default for Hook {
    fn default() -> Self {
        Self {
            lib: [0; MAX_NAME_LENGTH],
            proc: [0; MAX_NAME_LENGTH],
            proc_address: ptr::null_mut(),
            num_overridden: 0,
        }
    }
}

impl Hook {
    fn lib_name(&self) -> String {
        c_array_to_str(&self.lib)
    }

    fn proc_name(&self) -> String {
        c_array_to_str(&self.proc)
    }
}

#[derive(Default)]
struct BreakpointInfo {
    original_opcode: u8,
    hooks: Vec<Hook>,
}

struct ThreadInfo {
    thread: ThreadHandle,
    last_bp: *mut c_void,
}

impl ThreadInfo {
    fn new(thread: HANDLE) -> Self {
        Self {
            thread: ThreadHandle::new(thread),
            last_bp: ptr::null_mut(),
        }
    }
}

enum Resolution {
    Address(*mut c_void),
    Deferred,
}

#[derive(Clone, Copy, Default)]
struct PEExport {
    rva: u32,
    forwarded: bool,
}

#[derive(Default)]
struct HookLibrary {
    name: String,
    exports: HashMap<String, PEExport>,
    module: *mut c_void,
}

#[derive(Clone)]
struct LoaderCall {
    library: usize,
    proc: String,
    hook: *mut Hook,
    flag: *const FeatureFlagEntry,
}

#[derive(Clone, Copy)]
struct FeatureFlagEntry {
    lib: [u8; MAX_NAME_LENGTH],
    symbol: [u8; MAX_NAME_LENGTH],
}

impl Default for FeatureFlagEntry {
    fn default() -> Self {
        Self {
            lib: [0; MAX_NAME_LENGTH],
            symbol: [0; MAX_NAME_LENGTH],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExchangeData {
    module_base: *mut c_void,
    proc_address: *mut c_void,
    lib_name: [u8; MAX_NAME_LENGTH],
    proc_name: [u8; MAX_NAME_LENGTH],
}

impl Default for ExchangeData {
    fn default() -> Self {
        Self {
            module_base: ptr::null_mut(),
            proc_address: ptr::null_mut(),
            lib_name: [0; MAX_NAME_LENGTH],
            proc_name: [0; MAX_NAME_LENGTH],
        }
    }
}

struct HookBuffer {
    hooks: BTreeMap<usize, Vec<Hook>>,
    checksum: Crc32,
    count: usize,
}

impl HookBuffer {
    fn new() -> Self {
        Self {
            hooks: BTreeMap::new(),
            checksum: Crc32::new(),
            count: 0,
        }
    }

    fn add(&mut self, eip: *mut c_void, hook: Hook) {
        let overridden = hook.num_overridden as u32;
        self.hooks.entry(eip as usize).or_default().push(hook);

        let eip_bits = eip as usize as u32;
        self.checksum.compute(&eip_bits.to_le_bytes());
        self.checksum.compute(&overridden.to_le_bytes());
        self.count += 1;
    }

    fn add_named(&mut self, eip: *mut c_void, filename: &str, proc: &str, num_overridden: usize) {
        let mut hook = Hook {
            num_overridden,
            ..Default::default()
        };

        copy_name(&mut hook.lib, filename);
        copy_name(&mut hook.proc, proc);
        self.add(eip, hook);
    }
}

struct InstructionInfo {
    src_offset: usize,
    src_length: usize,
    intra_prologue: bool,
    target_src_offset: usize,
    output_size: usize,
    output_offset: usize,
    encoder_req: Option<EncoderRequest>,
}

struct Patch {
    address: usize,
    bytes: Vec<u8>,
    region_ends: Vec<usize>,
}

pub struct SyringeDebugger {
    exe: String,
    dlls: Vec<String>,

    pc_entry_point: *mut c_void,
    p_im_load_library: *mut c_void,
    p_im_get_proc_address: *mut c_void,
    p_loader_code: VirtualMemoryHandle,
    p_exchange_data: VirtualMemoryHandle,
    dw_time_stamp: u32,
    dw_exe_size: u32,
    dw_exe_crc: u32,

    b_detach_when_done: bool,
    b_wait_for_process_end: bool,
    b_handshakes: bool,

    b_entry_bp: bool,
    b_dlls_loaded: bool,
    b_hooks_created: bool,
    b_av_logged: bool,

    threads: BTreeMap<u32, ThreadInfo>,
    p_info: PROCESS_INFORMATION,
    working_handle: HANDLE,

    breakpoints: BTreeMap<usize, BreakpointInfo>,
    v_all_hooks: Vec<*mut Hook>,
    p_caller_code: VirtualMemoryHandle,

    v_libraries: Vec<HookLibrary>,
    v_loader_calls: Vec<LoaderCall>,
    loader_next: usize,
    b_loader_started: bool,
    b_exports_resolved: bool,
    v_feature_flags: Vec<FeatureFlagEntry>,
}

impl SyringeDebugger {
    pub fn new(filename: &str, flags: Vec<String>) -> Result<Self, LastError> {
        let mut this = Self {
            exe: filename.to_string(),
            dlls: Vec::new(),
            pc_entry_point: ptr::null_mut(),
            p_im_load_library: ptr::null_mut(),
            p_im_get_proc_address: ptr::null_mut(),
            p_loader_code: VirtualMemoryHandle::default(),
            p_exchange_data: VirtualMemoryHandle::default(),
            dw_time_stamp: 0,
            dw_exe_size: 0,
            dw_exe_crc: 0,
            b_detach_when_done: false,
            b_wait_for_process_end: true,
            b_handshakes: false,
            b_entry_bp: true,
            b_dlls_loaded: false,
            b_hooks_created: false,
            b_av_logged: false,
            threads: BTreeMap::new(),
            p_info: unsafe { zeroed() },
            working_handle: ptr::null_mut(),
            breakpoints: BTreeMap::new(),
            v_all_hooks: Vec::new(),
            p_caller_code: VirtualMemoryHandle::default(),
            v_libraries: Vec::new(),
            v_loader_calls: Vec::new(),
            loader_next: 0,
            b_loader_started: false,
            b_exports_resolved: false,
            v_feature_flags: Vec::new(),
        };

        for flag in &flags {
            if let Some(position) = flag.find(INCLUDE_FLAG) {
                this.dlls
                    .push(flag[position + INCLUDE_FLAG.len()..].to_string());
            } else if flag.contains(DETACH_FLAG) {
                this.b_detach_when_done = true;
            } else if flag.contains(NODETACH_FLAG) {
                this.b_detach_when_done = false;
            } else if flag.contains(NOWAIT_FLAG) {
                this.b_wait_for_process_end = false;
            } else if flag.contains(HANDSHAKES_FLAG) {
                this.b_handshakes = true;
            } else {
                log_line!("new", "Unknown flag \"{}\", skipping.", flag);
            }
        }

        if this.dlls.is_empty() {
            this.dlls.push("*.dll".to_string());
        }

        this.retrieve_info()?;
        Ok(this)
    }

    fn get_data(&self) -> *mut ExchangeData {
        self.p_exchange_data.get() as *mut ExchangeData
    }

    fn get_loader_code(&self) -> *mut u8 {
        self.p_loader_code.get()
    }

    // ---------------------------------------------------------------- memory

    pub fn patch_mem(&self, address: *mut c_void, buffer: *const c_void, size: u32) -> bool {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                self.working_handle,
                address,
                buffer,
                size as usize,
                &mut written,
            ) != 0
        }
    }

    pub fn patch_code(&self, address: *mut c_void, buffer: *const c_void, size: u32) -> bool {
        self.patch_mem(address, buffer, size)
            && unsafe { FlushInstructionCache(self.working_handle, address, size as usize) != 0 }
    }

    pub fn read_mem(&self, address: *const c_void, buffer: *mut c_void, size: u32) -> bool {
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.working_handle,
                address,
                buffer,
                size as usize,
                &mut read,
            ) != 0
        };
        ok && read == size as usize
    }

    /// Forwards a debuggee `OutputDebugString` message to the injector log.
    fn log_debug_string(
        &self,
        info: windows_sys::Win32::System::Diagnostics::Debug::OUTPUT_DEBUG_STRING_INFO,
    ) {
        let length = info.nDebugStringLength as usize;
        if length == 0 || info.lpDebugStringData.is_null() {
            return;
        }

        let mut bytes = vec![0u8; length];
        if !self.read_mem(
            info.lpDebugStringData as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            length as u32,
        ) {
            log_line!(
                "log_debug_string",
                "Could not read debug string at {:p}.",
                info.lpDebugStringData
            );
            return;
        }

        let text = if info.fUnicode != 0 {
            let words: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            String::from_utf16_lossy(&words)
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };

        log_line!("log_debug_string", "{}", text.trim_end_matches('\0'));
    }

    pub fn alloc_mem(
        &self,
        address: *mut c_void,
        size: usize,
    ) -> Result<VirtualMemoryHandle, LastError> {
        let memory = VirtualMemoryHandle::new(self.working_handle, address, size);
        if !memory.is_valid() {
            return Err(throw_lasterror_or(
                ERROR_ERRORS_ENCOUNTERED as u32,
                self.exe.clone(),
            ));
        }
        Ok(memory)
    }

    pub fn make_executable(
        &self,
        memory: &VirtualMemoryHandle,
        size: usize,
    ) -> Result<(), LastError> {
        if !memory.protect(size, PAGE_EXECUTE_READ) {
            return Err(throw_memory_error(
                "VirtualProtectEx",
                memory.get() as *mut c_void,
                size,
                &self.exe,
            ));
        }

        if !memory.flush_instruction_cache(size) {
            return Err(throw_memory_error(
                "FlushInstructionCache",
                memory.get() as *mut c_void,
                size,
                &self.exe,
            ));
        }

        Ok(())
    }

    // ----------------------------------------------------------- breakpoints

    pub fn set_bp(&mut self, address: *mut c_void) -> bool {
        let key = address as usize;

        // C++ does `Breakpoints[address].original_opcode`, which inserts the entry
        // before the read. If the read fails, the opcode remains zero and the
        // breakpoint is still written.
        let existing = self
            .breakpoints
            .get(&key)
            .map(|info| info.original_opcode)
            .unwrap_or(0);

        if existing != 0 {
            return true;
        }

        let mut opcode = 0u8;
        if !self.read_mem(address, &mut opcode as *mut u8 as *mut c_void, 1) {
            return false;
        }

        let info = self.breakpoints.entry(key).or_default();
        info.original_opcode = opcode;

        if !self.patch_code(address, &INT3 as *const u8 as *const c_void, 1) {
            return false;
        }

        true
    }

    pub fn remove_bp(
        &mut self,
        address: *mut c_void,
        restore_opcode: bool,
    ) -> Result<(), LastError> {
        let Some(original_opcode) = self
            .breakpoints
            .get(&(address as usize))
            .map(|info| info.original_opcode)
        else {
            return Ok(());
        };

        if restore_opcode
            && !self.patch_code(address, &original_opcode as *const u8 as *const c_void, 1)
        {
            return Err(throw_lasterror_or(
                ERROR_ERRORS_ENCOUNTERED as u32,
                self.exe.clone(),
            ));
        }

        self.breakpoints.remove(&(address as usize));

        Ok(())
    }

    fn relative_offset(from: *const c_void, to: *const c_void) -> u32 {
        (to as usize as u32).wrapping_sub(from as usize as u32)
    }

    // ----------------------------------------------------------- information

    fn retrieve_info(&mut self) -> Result<(), LastError> {
        log_line!(
            "retrieve_info",
            "Retrieving info from the executable file..."
        );

        let pe = match PortableExecutable::new(&self.exe) {
            Ok(pe) => pe,
            Err(error) => {
                log_line!("retrieve_info", "Failed to open the executable!");
                return Err(error);
            }
        };

        let image_base = pe.image_base();
        self.dw_time_stamp = pe.pe_header().FileHeader.TimeDateStamp;
        self.pc_entry_point = (image_base
            .wrapping_add(pe.pe_header().OptionalHeader.AddressOfEntryPoint))
            as usize as *mut c_void;

        self.p_im_load_library = ptr::null_mut();
        self.p_im_get_proc_address = ptr::null_mut();

        for import in pe.imports() {
            if !import.name.eq_ignore_ascii_case("KERNEL32.DLL") {
                continue;
            }

            for thunk in &import.thunks {
                if thunk.name.eq_ignore_ascii_case("GETPROCADDRESS") {
                    self.p_im_get_proc_address =
                        image_base.wrapping_add(thunk.address) as usize as *mut c_void;
                } else if thunk.name.eq_ignore_ascii_case("LOADLIBRARYA") {
                    self.p_im_load_library =
                        image_base.wrapping_add(thunk.address) as usize as *mut c_void;
                }
            }
        }

        if self.p_im_load_library.is_null() || self.p_im_get_proc_address.is_null() {
            log_line!(
                "retrieve_info",
                "ERROR: Either a LoadLibraryA or a GetProcAddress import could not be found!"
            );
            return Err(throw_lasterror_or(
                ERROR_PROC_NOT_FOUND as u32,
                self.exe.clone(),
            ));
        }

        if let Ok(mut file) = std::fs::File::open(&self.exe) {
            use std::io::{Read, Seek, SeekFrom};

            if let Ok(metadata) = file.metadata() {
                self.dw_exe_size = metadata.len() as u32;
            }

            if file.seek(SeekFrom::Start(0)).is_ok() {
                let mut crc = Crc32::new();
                let mut buffer = [0u8; 0x1000];

                loop {
                    match file.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            crc.compute(&buffer[..count]);
                        }
                    }
                }

                self.dw_exe_crc = crc.value();
            }
        }

        log_line!(
            "retrieve_info",
            "Executable information successfully retrieved."
        );
        log_line!("retrieve_info", "\texe = {}", self.exe);
        log_line!(
            "retrieve_info",
            "\tpImLoadLibrary = 0x{:08X}",
            self.p_im_load_library as usize
        );
        log_line!(
            "retrieve_info",
            "\tpImGetProcAddress = 0x{:08X}",
            self.p_im_get_proc_address as usize
        );
        log_line!(
            "retrieve_info",
            "\tpcEntryPoint = 0x{:08X}",
            self.pc_entry_point as usize
        );
        log_line!("retrieve_info", "\tdwExeSize = 0x{:08X}", self.dw_exe_size);
        log_line!("retrieve_info", "\tdwExeCRC = 0x{:08X}", self.dw_exe_crc);
        log_line!(
            "retrieve_info",
            "\tdwTimestamp = 0x{:08X}",
            self.dw_time_stamp
        );
        log_line!();
        log_line!(
            "retrieve_info",
            "Opening {} to determine imports.",
            self.exe
        );

        Ok(())
    }

    // ---------------------------------------------------------- instructions

    pub fn rebuild_instructions(
        bytes: &[u8],
        original_addr: u32,
        new_addr: u32,
        hook_libraries: &str,
    ) -> Vec<u8> {
        let size = bytes.len();
        let hook_context = if hook_libraries.is_empty() {
            String::new()
        } else {
            format!(" in DLL(s): {}", hook_libraries)
        };

        let decoder = Decoder::new32();
        let mut infos: Vec<InstructionInfo> = Vec::new();
        let mut offset = 0usize;
        let mut out_off = 0usize;
        let mut tail_offset = size;

        while offset < size {
            let src_addr = original_addr.wrapping_add(offset as u32);
            let decoded = decoder.decode_first::<AllOperands>(&bytes[offset..]);

            let instruction = match decoded {
                Ok(Some(instruction)) => instruction,
                _ => {
                    log_line!(
                        "rebuild_instructions",
                        "Failed to decode instruction at 0x{:08X}, copying remaining {} bytes verbatim. This could mean there is a faulty return 0 hook at 0x{:08X}{}.",
                        src_addr,
                        size - offset,
                        original_addr,
                        hook_context
                    );
                    tail_offset = offset;
                    break;
                }
            };

            let operands = instruction.operands();
            let mut info = InstructionInfo {
                src_offset: offset,
                src_length: instruction.length as usize,
                intra_prologue: false,
                target_src_offset: 0,
                output_size: instruction.length as usize,
                output_offset: 0,
                encoder_req: None,
            };

            if instruction
                .attributes
                .contains(InstructionAttributes::IS_RELATIVE)
            {
                let has_near_form = matches!(
                    instruction.meta.category,
                    InstructionCategory::COND_BR
                        | InstructionCategory::UNCOND_BR
                        | InstructionCategory::CALL
                ) && !matches!(
                    instruction.mnemonic,
                    Mnemonic::LOOP
                        | Mnemonic::LOOPE
                        | Mnemonic::LOOPNE
                        | Mnemonic::JCXZ
                        | Mnemonic::JECXZ
                        | Mnemonic::JRCXZ
                );

                for operand in operands
                    .iter()
                    .take(instruction.operand_count_visible as usize)
                {
                    if let ffi::DecodedOperandKind::Imm(_) = &operand.kind {
                        if let Ok(abs_addr) =
                            instruction.calc_absolute_address(src_addr as u64, operand)
                        {
                            if abs_addr >= original_addr as u64
                                && abs_addr < (original_addr as u64 + size as u64)
                            {
                                if has_near_form {
                                    info.intra_prologue = true;
                                    info.target_src_offset =
                                        (abs_addr - original_addr as u64) as usize;
                                } else {
                                    log_line!(
                                        "rebuild_instructions",
                                        "Relative instruction at 0x{:08X} has an intra-prologue target but no near encoding. Hook at 0x{:08X}{} may not work correctly.",
                                        src_addr,
                                        original_addr,
                                        hook_context
                                    );
                                }
                            }
                        }
                        break;
                    }
                }

                // C++ ignores conversion failure and leaves the request empty, which
                // makes pass 2 copy the original instruction verbatim. Build the
                // request through the raw API so a failure does not panic.
                let mut request = EncoderRequest::new32(instruction.mnemonic);
                let status = unsafe {
                    ffi::ZydisEncoderDecodedInstructionToEncoderRequest(
                        &*instruction,
                        operands.as_ptr(),
                        instruction.operand_count_visible,
                        &mut *request,
                    )
                };

                if !status.is_error() {
                    resolve_relative_operands(
                        &mut request,
                        &instruction,
                        operands,
                        src_addr as u64,
                    );

                    if has_near_form {
                        request = request
                            .set_branch_type(BranchType::NEAR)
                            .set_branch_width(BranchWidth::_32);
                    }

                    info.encoder_req = Some(request);

                    if has_near_form {
                        info.output_size =
                            if instruction.meta.category == InstructionCategory::COND_BR {
                                6
                            } else {
                                5
                            };
                    }
                }
            }

            info.output_offset = out_off;
            out_off = out_off.wrapping_add(info.output_size);

            infos.push(info);
            offset += instruction.length as usize;
        }

        let mut result = Vec::with_capacity(size * 2);

        for index in 0..infos.len() {
            let info = &infos[index];
            let src_addr = original_addr.wrapping_add(info.src_offset as u32);
            let dst_addr = new_addr.wrapping_add(result.len() as u32);

            let Some(request) = &info.encoder_req else {
                result
                    .extend_from_slice(&bytes[info.src_offset..info.src_offset + info.src_length]);
                continue;
            };

            let mut request = request.clone();

            if info.intra_prologue {
                let encoder_operands = request.operands_mut();

                for operand in encoder_operands.iter_mut() {
                    if operand.ty == OperandType::IMMEDIATE {
                        for target in &infos {
                            if target.src_offset == info.target_src_offset {
                                operand.imm = new_addr as u64 + target.output_offset as u64;
                                break;
                            }
                        }
                        break;
                    }
                }
            }

            let mut encoded = [0u8; 15];
            let mut encoded_len = encoded.len();
            let status = unsafe {
                ffi::ZydisEncoderEncodeInstructionAbsolute(
                    &*request,
                    encoded.as_mut_ptr() as *mut c_void,
                    &mut encoded_len,
                    dst_addr as u64,
                )
            };

            if status.is_error() {
                log_line!(
                    "rebuild_instructions",
                    "Failed to re-encode instruction at 0x{:08X}, copying {} bytes verbatim. This could mean there is a faulty return 0 hook at 0x{:08X}.",
                    src_addr,
                    info.src_length,
                    original_addr
                );
                result
                    .extend_from_slice(&bytes[info.src_offset..info.src_offset + info.src_length]);
            } else {
                result.extend_from_slice(&encoded[..encoded_len]);
            }
        }

        if tail_offset < size {
            result.extend_from_slice(&bytes[tail_offset..]);
        }

        result
    }
}

// ---------------------------------------------------------------- helpers

fn c_char_array_to_str(array: &[i8]) -> String {
    let bytes: Vec<u8> = array.iter().map(|&value| value as u8).collect();
    c_array_to_str(&bytes)
}

fn c_array_to_str(array: &[u8]) -> String {
    let end = array
        .iter()
        .position(|&value| value == 0)
        .unwrap_or(array.len());
    String::from_utf8_lossy(&array[..end]).into_owned()
}

fn copy_name(destination: &mut [u8; MAX_NAME_LENGTH], source: &str) {
    let count = source.len().min(MAX_NAME_LENGTH - 1);
    destination[..count].copy_from_slice(&source.as_bytes()[..count]);
    destination[count] = 0;
}

// `sscanf("%x")` accepts a hex prefix and ignores trailing non-hex text.
fn parse_hex_prefix(text: &str) -> Option<u32> {
    let text = text.trim_start();
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let digits = text.bytes().take_while(u8::is_ascii_hexdigit).count();

    if digits == 0 {
        return None;
    }

    u32::from_str_radix(&text[..digits], 16).ok()
}

fn throw_memory_error(operation: &str, address: *mut c_void, size: usize, exe: &str) -> LastError {
    let mut error = unsafe { GetLastError() };
    if error == 0 {
        error = ERROR_ERRORS_ENCOUNTERED;
    }

    log_line!(
        "throw_memory_error",
        "{} failed at {:p} (size={}, error={}).",
        operation,
        address,
        size,
        error
    );

    throw_lasterror(error, exe.to_string())
}

fn apply_patch<T: Copy>(destination: *mut u8, value: T) {
    unsafe {
        ptr::copy_nonoverlapping(&value as *const T as *const u8, destination, size_of::<T>());
    }
}

fn resolve_relative_operands(
    request: &mut EncoderRequest,
    instruction: &ffi::DecodedInstruction,
    operands: &[ffi::DecodedOperand],
    src_addr: u64,
) {
    let encoder_operands = request.operands_mut();

    for index in 0..encoder_operands.len() {
        let operand = &operands[index];

        match &operand.kind {
            ffi::DecodedOperandKind::Imm(_) => {
                if let Ok(address) = instruction.calc_absolute_address(src_addr, operand) {
                    encoder_operands[index].imm = address;
                }
            }
            ffi::DecodedOperandKind::Mem(_) => {
                if let Ok(address) = instruction.calc_absolute_address(src_addr, operand) {
                    encoder_operands[index].mem.displacement = address as i64;
                }
            }
            _ => {}
        }
    }
}

impl SyringeDebugger {
    // ---------------------------------------------------------- exceptions

    pub fn handle_exception(&mut self, dbg_event: &DEBUG_EVENT) -> Result<i32, LastError> {
        let exception = unsafe { &dbg_event.u.Exception.ExceptionRecord };
        let except_code = exception.ExceptionCode;
        let except_addr = exception.ExceptionAddress;

        if except_code == EXCEPTION_BREAKPOINT {
            let thread_id = dbg_event.dwThreadId;
            let (current_thread, last_bp) = {
                let thread_info = self
                    .threads
                    .entry(thread_id)
                    .or_insert_with(|| ThreadInfo::new(ptr::null_mut()));
                (thread_info.thread.get(), thread_info.last_bp)
            };

            let mut context: CONTEXT = unsafe { zeroed() };
            context.ContextFlags = CONTEXT_CONTROL_X86;
            unsafe { GetThreadContext(current_thread, &mut context) };

            if self.b_entry_bp {
                self.b_entry_bp = false;
                return Ok(windows_sys::Win32::Foundation::DBG_CONTINUE);
            }

            if context.EFlags & 0x100 != 0 {
                context.EFlags &= !0x100;
                let buffer = INT3;
                if !self.patch_code(last_bp, &buffer as *const u8 as *const c_void, 1) {
                    return Err(throw_lasterror_or(
                        ERROR_ERRORS_ENCOUNTERED as u32,
                        self.exe.clone(),
                    ));
                }
            }

            if !self.b_dlls_loaded {
                let original_opcode = self
                    .breakpoints
                    .entry(except_addr as usize)
                    .or_default()
                    .original_opcode;

                if !self.patch_code(
                    except_addr,
                    &original_opcode as *const u8 as *const c_void,
                    1,
                ) {
                    return Err(throw_lasterror_or(
                        ERROR_ERRORS_ENCOUNTERED as u32,
                        self.exe.clone(),
                    ));
                }

                if self.b_loader_started {
                    let call = self.v_loader_calls[self.loader_next].clone();
                    self.loader_next += 1;
                    self.finish_loader_call(&call)?;
                }

                self.b_loader_started = true;

                if self.loader_next == self.v_loader_calls.len() && !self.b_exports_resolved {
                    self.b_exports_resolved = true;
                    self.resolve_from_exports()?;
                }

                if self.loader_next < self.v_loader_calls.len() {
                    let call = self.v_loader_calls[self.loader_next].clone();
                    self.start_loader_call(&call)?;
                    context.Eip = self.get_loader_code() as usize as u32;
                } else {
                    log_line!("handle_exception", "Finished retrieving proc addresses.");

                    if !self.v_feature_flags.is_empty() {
                        log_line!("handle_exception", "Finished setting feature flags.");
                    }

                    self.b_dlls_loaded = true;
                    context.Eip = self.pc_entry_point as usize as u32;
                }

                context.EFlags |= 0x100;
                context.ContextFlags = CONTEXT_CONTROL_X86;
                unsafe { SetThreadContext(current_thread, &context) };

                self.threads.get_mut(&thread_id).unwrap().last_bp = except_addr;

                return Ok(windows_sys::Win32::Foundation::DBG_CONTINUE);
            }

            if except_addr == self.pc_entry_point {
                if !self.b_hooks_created {
                    log_line!("handle_exception", "Creating code hooks.");

                    self.create_hooks()?;
                }

                let original_opcode = self
                    .breakpoints
                    .entry(except_addr as usize)
                    .or_default()
                    .original_opcode;

                if !self.patch_code(
                    except_addr,
                    &original_opcode as *const u8 as *const c_void,
                    1,
                ) {
                    return Err(throw_lasterror_or(
                        ERROR_ERRORS_ENCOUNTERED as u32,
                        self.exe.clone(),
                    ));
                }

                context.EFlags |= 0x100;
                context.Eip = context.Eip.wrapping_sub(1);
                context.ContextFlags = CONTEXT_CONTROL_X86;
                unsafe { SetThreadContext(current_thread, &context) };

                self.threads.get_mut(&thread_id).unwrap().last_bp = except_addr;

                return Ok(windows_sys::Win32::Foundation::DBG_CONTINUE);
            } else {
                context.ContextFlags = CONTEXT_CONTROL_X86;
                unsafe { SetThreadContext(current_thread, &context) };
                return Ok(DBG_EXCEPTION_NOT_HANDLED);
            }
        } else if except_code == EXCEPTION_SINGLE_STEP {
            let thread_id = dbg_event.dwThreadId;
            let thread_handle = {
                let thread_info = self
                    .threads
                    .entry(thread_id)
                    .or_insert_with(|| ThreadInfo::new(ptr::null_mut()));
                thread_info.thread.get()
            };
            let last_bp = self.threads.get(&thread_id).unwrap().last_bp;
            let buffer = INT3;

            if !self.patch_code(last_bp, &buffer as *const u8 as *const c_void, 1) {
                return Err(throw_lasterror_or(
                    ERROR_ERRORS_ENCOUNTERED as u32,
                    self.exe.clone(),
                ));
            }

            let mut context: CONTEXT = unsafe { zeroed() };
            context.ContextFlags = CONTEXT_CONTROL_X86;
            unsafe { GetThreadContext(thread_handle, &mut context) };

            context.EFlags &= !0x100;
            context.ContextFlags = CONTEXT_CONTROL_X86;
            unsafe { SetThreadContext(thread_handle, &context) };

            return Ok(windows_sys::Win32::Foundation::DBG_CONTINUE);
        } else {
            log_line!(
                "handle_exception",
                "Exception (Code: 0x{:08X} at 0x{:08X})!",
                except_code,
                except_addr as usize
            );

            if !self.b_av_logged {
                let thread_id = dbg_event.dwThreadId;
                let current_thread = self
                    .threads
                    .entry(thread_id)
                    .or_insert_with(|| ThreadInfo::new(ptr::null_mut()))
                    .thread
                    .get();

                let access = match exception.ExceptionInformation[0] {
                    0 => "read from",
                    1 => "write to",
                    8 => "execute",
                    _ => "",
                };

                log_line!(
                    "handle_exception",
                    "\tThe process tried to {} 0x{:08X}.",
                    access,
                    exception.ExceptionInformation[1]
                );

                let mut context: CONTEXT = unsafe { zeroed() };
                context.ContextFlags = CONTEXT_FULL_X86;
                unsafe { GetThreadContext(current_thread, &mut context) };

                log_line!();
                log_line!("handle_exception", "Registers:");
                log_line!(
                    "handle_exception",
                    "\tEAX = 0x{:08X}\tECX = 0x{:08X}\tEDX = 0x{:08X}",
                    context.Eax,
                    context.Ecx,
                    context.Edx
                );
                log_line!(
                    "handle_exception",
                    "\tEBX = 0x{:08X}\tESP = 0x{:08X}\tEBP = 0x{:08X}",
                    context.Ebx,
                    context.Esp,
                    context.Ebp
                );
                log_line!(
                    "handle_exception",
                    "\tESI = 0x{:08X}\tEDI = 0x{:08X}\tEIP = 0x{:08X}",
                    context.Esi,
                    context.Edi,
                    context.Eip
                );
                log_line!();

                log_line!("handle_exception", "\tStack dump:");
                for index in 0..0x100usize {
                    let address = context.Esp.wrapping_add((index * 4) as u32);
                    let mut value = 0u32;
                    if self.read_mem(
                        address as usize as *const c_void,
                        &mut value as *mut u32 as *mut c_void,
                        4,
                    ) {
                        log_line!("handle_exception", "\t0x{:08X}:\t0x{:08X}", address, value);
                    } else {
                        log_line!(
                            "handle_exception",
                            "\t0x{:08X}:\t(could not be read)",
                            address
                        );
                    }
                }
                log_line!();

                self.b_av_logged = true;
            }

            Ok(DBG_EXCEPTION_NOT_HANDLED)
        }
    }

    // ------------------------------------------------------------- hooks

    fn create_hooks(&mut self) -> Result<(), LastError> {
        struct Site {
            address: usize,
            hooks: Vec<Hook>,
            overridden: usize,
            patch_end: usize,
            offset: usize,
            capacity: usize,
        }

        let mut sites: Vec<Site> = Vec::new();
        let mut total = 0usize;
        let caller_limit = u32::MAX as usize;
        let entry_point = self.pc_entry_point as usize;

        for (&address, info) in &self.breakpoints {
            if address == 0 || address == entry_point {
                continue;
            }

            let mut count = 0usize;
            let mut overridden = 0usize;

            for hook in &info.hooks {
                if !hook.proc_address.is_null() {
                    if overridden < hook.num_overridden {
                        overridden = hook.num_overridden;
                    }
                    count += 1;
                }
            }

            if count == 0 {
                continue;
            }

            let remaining = caller_limit - total;
            if remaining < JMP_BACK.len()
                || count > (remaining - JMP_BACK.len()) / CODE_CALL.len()
                || overridden > (remaining - JMP_BACK.len() - count * CODE_CALL.len()) / 3
            {
                log_line!(
                    "create_hooks",
                    "Caller size overflow at {:p} (hooks={}, overridden={}, total={}).",
                    address as *mut c_void,
                    count,
                    overridden,
                    total
                );
                return Err(throw_lasterror(
                    ERROR_ARITHMETIC_OVERFLOW as u32,
                    self.exe.clone(),
                ));
            }

            let capacity = count * CODE_CALL.len() + JMP_BACK.len() + overridden * 3;
            let patch_end = address
                .checked_add(overridden.max(JMP.len()))
                .ok_or_else(|| {
                    throw_lasterror(ERROR_ARITHMETIC_OVERFLOW as u32, self.exe.clone())
                })?;

            sites.push(Site {
                address,
                hooks: info.hooks.clone(),
                overridden,
                patch_end,
                offset: total,
                capacity,
            });
            total += capacity;
        }

        if !sites.is_empty() {
            self.p_caller_code = self.alloc_mem(ptr::null_mut(), total)?;
            let base = self.p_caller_code.get();
            let mut callers = Vec::new();
            if callers.try_reserve_exact(total).is_err() {
                return Err(throw_lasterror(
                    ERROR_NOT_ENOUGH_MEMORY as u32,
                    self.exe.clone(),
                ));
            }
            callers.resize(total, INT3);

            let mut patches: Vec<Patch> = Vec::new();

            let mut first = 0usize;
            while first < sites.len() {
                let mut region: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
                let query = unsafe {
                    VirtualQueryEx(
                        self.working_handle,
                        sites[first].address as usize as *const c_void,
                        &mut region,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if query == 0 {
                    return Err(throw_memory_error(
                        "VirtualQueryEx",
                        sites[first].address as usize as *mut c_void,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                        &self.exe,
                    ));
                }
                let mut region_end = (region.BaseAddress as usize)
                    .checked_add(region.RegionSize)
                    .unwrap_or(usize::MAX);

                let run_start = sites[first].address;
                let mut run_end = sites[first].patch_end;
                let mut last = first + 1;

                while last < sites.len()
                    && sites[last].address <= run_end.saturating_add(MAX_PATCH_GAP)
                    && (sites[last].patch_end <= region_end || sites[last].address < run_end)
                {
                    run_end = run_end.max(sites[last].patch_end);
                    last += 1;
                }

                let mut memory = vec![0u8; run_end - run_start];
                let mut region_ends: Vec<usize> = Vec::new();
                let mut offset = 0usize;

                while offset < memory.len() {
                    let end = run_end.min(region_end);
                    let size = (end - (run_start + offset)) as u32;

                    if !self.read_mem(
                        (run_start + offset) as usize as *const c_void,
                        memory[offset..].as_mut_ptr() as *mut c_void,
                        size,
                    ) {
                        return Err(throw_memory_error(
                            "ReadProcessMemory",
                            (run_start + offset) as usize as *mut c_void,
                            size as usize,
                            &self.exe,
                        ));
                    }

                    offset += size as usize;
                    region_ends.push(offset);

                    if offset < memory.len() {
                        let query = unsafe {
                            VirtualQueryEx(
                                self.working_handle,
                                (run_start + offset) as usize as *const c_void,
                                &mut region,
                                size_of::<MEMORY_BASIC_INFORMATION>(),
                            )
                        };
                        if query == 0 {
                            return Err(throw_memory_error(
                                "VirtualQueryEx",
                                (run_start + offset) as usize as *mut c_void,
                                size_of::<MEMORY_BASIC_INFORMATION>(),
                                &self.exe,
                            ));
                        }
                        region_end = (region.BaseAddress as usize)
                            .checked_add(region.RegionSize)
                            .unwrap_or(usize::MAX);
                    }
                }

                for site in &sites[first..last] {
                    let mut p_code = site.offset;
                    let caller_end = site.offset + site.capacity;
                    let remote = |local: usize| base as usize + local;

                    for hook in &site.hooks {
                        if hook.proc_address.is_null() {
                            continue;
                        }

                        callers[p_code..p_code + CODE_CALL.len()].copy_from_slice(&CODE_CALL);
                        apply_patch(
                            callers.as_mut_ptr().wrapping_add(p_code + 0x03),
                            site.address as u32,
                        );

                        let relative = Self::relative_offset(
                            remote(p_code + 0x0D) as *const c_void,
                            hook.proc_address,
                        );
                        apply_patch(callers.as_mut_ptr().wrapping_add(p_code + 0x09), relative);

                        p_code += CODE_CALL.len();
                    }

                    if site.overridden != 0 {
                        let mut rebuild_libraries = BTreeSet::new();
                        for hook in &site.hooks {
                            if !hook.proc_address.is_null()
                                && hook.num_overridden == site.overridden
                            {
                                rebuild_libraries.insert(hook.lib_name());
                            }
                        }

                        let mut rebuild_library_names = String::new();
                        for library in rebuild_libraries {
                            if !rebuild_library_names.is_empty() {
                                rebuild_library_names.push_str(", ");
                            }
                            rebuild_library_names.push('"');
                            rebuild_library_names.push_str(&library);
                            rebuild_library_names.push('"');
                        }

                        let rebuilt = Self::rebuild_instructions(
                            &memory[site.address - run_start
                                ..site.address - run_start + site.overridden],
                            site.address as u32,
                            remote(p_code) as u32,
                            &rebuild_library_names,
                        );

                        let remaining = caller_end - p_code;
                        if remaining < JMP_BACK.len() || rebuilt.len() > remaining - JMP_BACK.len()
                        {
                            log_line!(
                                "create_hooks",
                                "Caller buffer too small at {:p} (rebuilt={}, remaining={}, jump={}).",
                                site.address as *mut c_void,
                                rebuilt.len(),
                                remaining,
                                JMP_BACK.len()
                            );
                            return Err(throw_lasterror(
                                ERROR_INSUFFICIENT_BUFFER as u32,
                                self.exe.clone(),
                            ));
                        }

                        callers[p_code..p_code + rebuilt.len()].copy_from_slice(&rebuilt);
                        p_code += rebuilt.len();
                    }

                    let relative = Self::relative_offset(
                        remote(p_code + 0x05) as *const c_void,
                        (site.address + 0x05) as *const c_void,
                    );
                    callers[p_code..p_code + JMP_BACK.len()].copy_from_slice(&JMP_BACK);
                    apply_patch(callers.as_mut_ptr().wrapping_add(p_code + 0x01), relative);

                    let relative = Self::relative_offset(
                        (site.address + 5) as *const c_void,
                        remote(site.offset) as *const c_void,
                    );

                    let original = &mut memory[site.address - run_start..];
                    original[..site.overridden.max(JMP.len())].fill(NOP);
                    original[..JMP.len()].copy_from_slice(&JMP);
                    apply_patch(original.as_mut_ptr().wrapping_add(0x01), relative);
                }

                patches.push(Patch {
                    address: run_start,
                    bytes: memory,
                    region_ends,
                });

                first = last;
            }

            if !self.patch_mem(
                base as *mut c_void,
                callers.as_ptr() as *const c_void,
                callers.len() as u32,
            ) {
                return Err(throw_memory_error(
                    "WriteProcessMemory",
                    base as *mut c_void,
                    callers.len(),
                    &self.exe,
                ));
            }

            self.make_executable(&self.p_caller_code, total)?;

            for patch in &patches {
                let mut offset = 0usize;
                for &end in &patch.region_ends {
                    if !self.patch_code(
                        (patch.address + offset) as usize as *mut c_void,
                        patch.bytes[offset..].as_ptr() as *const c_void,
                        (end - offset) as u32,
                    ) {
                        return Err(throw_memory_error(
                            "PatchCode",
                            (patch.address + offset) as usize as *mut c_void,
                            end - offset,
                            &self.exe,
                        ));
                    }
                    offset = end;
                }
            }
        }

        crate::log::Log::flush();

        self.b_hooks_created = true;
        Ok(())
    }
}

impl SyringeDebugger {
    // -------------------------------------------------------------- process

    fn debug_process(&mut self, arguments: &str) -> Result<(), LastError> {
        let mut startup_info: STARTUPINFOA = unsafe { zeroed() };
        startup_info.cb = size_of::<STARTUPINFOA>() as u32;

        unsafe {
            SetEnvironmentVariableA(b"_NO_DEBUG_HEAP\0".as_ptr(), b"1\0".as_ptr());
        }

        let command_line = format!("\"{}\" {}", self.exe, arguments);
        let mut command_line = command_line.into_bytes();
        command_line.push(0);

        let application_name = CString::new(self.exe.clone()).unwrap();

        let created = unsafe {
            CreateProcessA(
                application_name.as_ptr() as *const u8,
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
                ptr::null(),
                ptr::null(),
                &startup_info,
                &mut self.p_info,
            )
        };

        if created == 0 {
            return Err(throw_lasterror_or(
                ERROR_ERRORS_ENCOUNTERED as u32,
                self.exe.clone(),
            ));
        }

        self.working_handle = self.p_info.hProcess;
        Ok(())
    }

    pub fn run(&mut self, arguments: &str) -> Result<(), LastError> {
        log_line!(
            "run",
            "Running process to debug. cmd = \"{} {}\"",
            self.exe,
            arguments
        );
        self.debug_process(arguments)?;

        log_line!("run", "Writing DLL loader & caller code...");

        let mut code = C_LOAD_LIBRARY;
        self.p_loader_code = self.alloc_mem(ptr::null_mut(), code.len())?;
        self.p_exchange_data = self.alloc_mem(ptr::null_mut(), size_of::<ExchangeData>())?;

        let data = self.get_data();

        apply_patch(
            code.as_mut_ptr().wrapping_add(0x04),
            unsafe { ptr::addr_of!((*data).lib_name) } as usize as u32,
        );
        apply_patch(
            code.as_mut_ptr().wrapping_add(0x0A),
            self.p_im_load_library as usize as u32,
        );
        apply_patch(code.as_mut_ptr().wrapping_add(0x0F), unsafe {
            ptr::addr_of!((*data).module_base)
        } as usize
            as u32);
        apply_patch(code.as_mut_ptr().wrapping_add(0x18), unsafe {
            ptr::addr_of!((*data).proc_name)
        } as usize
            as u32);
        apply_patch(
            code.as_mut_ptr().wrapping_add(0x1F),
            self.p_im_get_proc_address as usize as u32,
        );
        apply_patch(code.as_mut_ptr().wrapping_add(0x24), unsafe {
            ptr::addr_of!((*data).proc_address)
        } as usize
            as u32);

        if !self.patch_mem(
            self.get_loader_code() as *mut c_void,
            code.as_ptr() as *const c_void,
            code.len() as u32,
        ) {
            return Err(throw_lasterror_or(
                ERROR_ERRORS_ENCOUNTERED as u32,
                self.exe.clone(),
            ));
        }

        self.make_executable(&self.p_loader_code, code.len())?;

        log_line!(
            "run",
            "pcLoadLibrary = 0x{:08X}",
            self.get_loader_code() as usize
        );

        self.b_dlls_loaded = false;
        self.b_hooks_created = false;

        self.v_loader_calls.clear();
        for library in 0..self.v_libraries.len() {
            self.v_loader_calls.push(LoaderCall {
                library,
                proc: String::new(),
                hook: ptr::null_mut(),
                flag: ptr::null(),
            });
        }

        self.loader_next = 0;
        self.b_loader_started = false;
        self.b_exports_resolved = false;

        if !self.set_bp(self.pc_entry_point) {
            return Err(throw_lasterror_or(
                ERROR_ERRORS_ENCOUNTERED as u32,
                self.exe.clone(),
            ));
        }

        unsafe { ResumeThread(self.p_info.hThread) };

        self.b_av_logged = false;

        log_line!("run", "Entering debug loop...");

        let mut exit_code = u32::MAX;

        loop {
            let mut dbg_event: DEBUG_EVENT = unsafe { zeroed() };
            unsafe { WaitForDebugEvent(&mut dbg_event, INFINITE) };

            let mut continue_status = windows_sys::Win32::Foundation::DBG_CONTINUE;
            let mut was_single_step = false;

            match dbg_event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { dbg_event.u.CreateProcessInfo };
                    self.working_handle = info.hProcess;
                    self.threads
                        .entry(dbg_event.dwThreadId)
                        .or_insert_with(|| ThreadInfo::new(info.hThread));
                    unsafe { CloseHandle(info.hFile) };
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let info = unsafe { dbg_event.u.CreateThread };
                    self.threads
                        .entry(dbg_event.dwThreadId)
                        .or_insert_with(|| ThreadInfo::new(info.hThread));
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    if let Some(mut info) = self.threads.remove(&dbg_event.dwThreadId) {
                        info.thread.release();
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    continue_status = self.handle_exception(&dbg_event)?;
                    was_single_step = unsafe {
                        dbg_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
                    };
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { dbg_event.u.LoadDll };
                    unsafe { CloseHandle(info.hFile) };
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    let info = unsafe { dbg_event.u.DebugString };
                    self.log_debug_string(info);
                }
                _ => {}
            }

            if dbg_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                exit_code = unsafe { dbg_event.u.ExitProcess.dwExitCode };
                unsafe {
                    ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status)
                };
                break;
            } else if dbg_event.dwDebugEventCode == RIP_EVENT {
                unsafe {
                    ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status)
                };
                break;
            }

            unsafe {
                ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status)
            };

            if self.b_detach_when_done && self.b_hooks_created && was_single_step {
                log_line!("run", "Hooks placed, detaching debugger.");

                if unsafe { DebugActiveProcessStop(dbg_event.dwProcessId) } == 0 {
                    log_line!("run", "DebugActiveProcessStop failed ({}).", unsafe {
                        GetLastError()
                    });
                }

                break;
            }
        }

        self.working_handle = ptr::null_mut();

        if self.b_wait_for_process_end {
            log_line!("run", "Waiting for process to exit...");

            unsafe { WaitForSingleObject(self.p_info.hProcess, INFINITE) };

            if unsafe { GetExitCodeProcess(self.p_info.hProcess, &mut exit_code) } == 0 {
                log_line!("run", "Failed to get process exit code!");
            }
        }

        unsafe { CloseHandle(self.p_info.hProcess) };

        log_line!(
            "run",
            "Done with exit code {:X} ({}).",
            exit_code,
            exit_code
        );
        log_line!();

        Ok(())
    }

    // -------------------------------------------------------------- loaders

    fn start_loader_call(&mut self, call: &LoaderCall) -> Result<(), LastError> {
        let mut request: ExchangeData = unsafe { zeroed() };
        copy_name(&mut request.lib_name, &self.v_libraries[call.library].name);
        copy_name(&mut request.proc_name, &call.proc);

        if !self.patch_mem(
            self.get_data() as *mut c_void,
            &request as *const ExchangeData as *const c_void,
            size_of::<ExchangeData>() as u32,
        ) {
            return Err(throw_memory_error(
                "WriteProcessMemory",
                self.get_data() as *mut c_void,
                size_of::<ExchangeData>(),
                &self.exe,
            ));
        }

        Ok(())
    }

    fn finish_loader_call(&mut self, call: &LoaderCall) -> Result<(), LastError> {
        let mut results = [0u32; 2];
        if !self.read_mem(
            unsafe { ptr::addr_of!((*self.get_data()).module_base) } as *const c_void,
            results.as_mut_ptr() as *mut c_void,
            size_of::<[u32; 2]>() as u32,
        ) {
            return Err(throw_memory_error(
                "ReadProcessMemory",
                unsafe { ptr::addr_of!((*self.get_data()).module_base) } as *mut c_void,
                size_of::<[u32; 2]>(),
                &self.exe,
            ));
        }

        let module = results[0] as usize as *mut c_void;
        let address = results[1] as usize as *mut c_void;

        if !call.hook.is_null() {
            unsafe {
                (*call.hook).proc_address = address;
            }

            if address.is_null() {
                let hook = unsafe { &*call.hook };
                log_line!(
                    "finish_loader_call",
                    "Could not retrieve ProcAddress for: {} - {}",
                    hook.lib_name(),
                    hook.proc_name()
                );
            }
        } else if !call.flag.is_null() {
            let flag = unsafe { &*call.flag };
            self.apply_feature_flag(flag, address)?;
        } else {
            self.v_libraries[call.library].module = module;

            if module.is_null() {
                log_line!(
                    "finish_loader_call",
                    "Could not load \"{}\".",
                    self.v_libraries[call.library].name
                );
            }
        }

        Ok(())
    }

    fn read_module_exports(
        &self,
        module: *mut c_void,
        exports: &mut HashMap<String, PEExport>,
    ) -> bool {
        exports.clear();

        let base = module as *mut u8;
        let mut dos: IMAGE_DOS_HEADER = unsafe { zeroed() };
        let mut nt: IMAGE_NT_HEADERS32 = unsafe { zeroed() };

        if !self.read_mem(
            base as *const c_void,
            &mut dos as *mut IMAGE_DOS_HEADER as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>() as u32,
        ) || dos.e_magic != IMAGE_DOS_SIGNATURE
            || dos.e_lfanew < 0
            || !self.read_mem(
                base.wrapping_add(dos.e_lfanew as usize) as *const c_void,
                &mut nt as *mut IMAGE_NT_HEADERS32 as *mut c_void,
                size_of::<IMAGE_NT_HEADERS32>() as u32,
            )
            || nt.Signature != IMAGE_NT_SIGNATURE
            || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
            || nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT as u32
        {
            return false;
        }

        let dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if dir.VirtualAddress == 0 && dir.Size == 0 {
            return true;
        }

        let image_size = nt.OptionalHeader.SizeOfImage;

        if dir.VirtualAddress == 0
            || dir.Size < size_of::<IMAGE_EXPORT_DIRECTORY>() as u32
            || dir.VirtualAddress >= image_size
            || dir.Size > image_size - dir.VirtualAddress
        {
            return false;
        }

        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(dir.Size as usize).is_err() {
            return false;
        }
        bytes.resize(dir.Size as usize, 0);
        if !self.read_mem(
            base.wrapping_add(dir.VirtualAddress as usize) as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            dir.Size,
        ) {
            return false;
        }

        let contains = |rva: u32, count: usize, element_size: usize| {
            if rva < dir.VirtualAddress {
                return false;
            }

            let offset = (rva - dir.VirtualAddress) as usize;
            offset <= bytes.len() && count <= (bytes.len() - offset) / element_size
        };

        let export_dir: IMAGE_EXPORT_DIRECTORY =
            unsafe { ptr::read_unaligned(bytes.as_ptr() as *const IMAGE_EXPORT_DIRECTORY) };

        if export_dir.NumberOfNames == 0 {
            return true;
        }

        if !contains(
            export_dir.AddressOfNames,
            export_dir.NumberOfNames as usize,
            size_of::<u32>(),
        ) || !contains(
            export_dir.AddressOfNameOrdinals,
            export_dir.NumberOfNames as usize,
            size_of::<u16>(),
        ) || !contains(
            export_dir.AddressOfFunctions,
            export_dir.NumberOfFunctions as usize,
            size_of::<u32>(),
        ) {
            return false;
        }

        for index in 0..export_dir.NumberOfNames {
            let name_rva = unsafe {
                ptr::read_unaligned(
                    bytes
                        .as_ptr()
                        .add((export_dir.AddressOfNames - dir.VirtualAddress) as usize)
                        .add(index as usize * size_of::<u32>()) as *const u32,
                )
            };
            let ordinal = unsafe {
                ptr::read_unaligned(
                    bytes
                        .as_ptr()
                        .add((export_dir.AddressOfNameOrdinals - dir.VirtualAddress) as usize)
                        .add(index as usize * size_of::<u16>()) as *const u16,
                )
            };

            if ordinal as u32 >= export_dir.NumberOfFunctions || !contains(name_rva, 1, 1) {
                return false;
            }

            let rva = unsafe {
                ptr::read_unaligned(
                    bytes
                        .as_ptr()
                        .add((export_dir.AddressOfFunctions - dir.VirtualAddress) as usize)
                        .add(ordinal as usize * size_of::<u32>()) as *const u32,
                )
            };

            if rva >= image_size {
                return false;
            }

            let name_offset = (name_rva - dir.VirtualAddress) as usize;
            let name = match bytes[name_offset..].iter().position(|&value| value == 0) {
                Some(length) => {
                    String::from_utf8_lossy(&bytes[name_offset..name_offset + length]).into_owned()
                }
                None => return false,
            };

            let forwarded = rva >= dir.VirtualAddress && rva - dir.VirtualAddress < dir.Size;
            exports.entry(name).or_insert(PEExport { rva, forwarded });
        }

        true
    }

    fn resolve_export(
        libraries: &[HookLibrary],
        usable: &[bool],
        index: usize,
        name: &str,
    ) -> Resolution {
        let library = &libraries[index];

        if library.module.is_null() {
            return Resolution::Address(ptr::null_mut());
        }

        if !usable[index] {
            return Resolution::Deferred;
        }

        let Some(export) = library.exports.get(name) else {
            return Resolution::Address(ptr::null_mut());
        };

        if export.rva == 0 {
            return Resolution::Address(ptr::null_mut());
        }

        if export.forwarded {
            return Resolution::Deferred;
        }

        Resolution::Address(
            (library.module as usize).wrapping_add(export.rva as usize) as *mut c_void
        )
    }

    fn resolve_from_exports(&mut self) -> Result<(), LastError> {
        let mut by_name: HashMap<String, usize> = HashMap::new();
        let mut usable = vec![false; self.v_libraries.len()];

        for index in 0..self.v_libraries.len() {
            let name = self.v_libraries[index].name.clone();
            let module = self.v_libraries[index].module;
            by_name.insert(name, index);

            if !module.is_null() {
                let mut exports = HashMap::new();
                usable[index] = self.read_module_exports(module, &mut exports);

                // C++ clears the library's export map on entry to
                // ReadModuleExports, even when the read ultimately fails, so
                // keep any partial result here as well.
                self.v_libraries[index].exports = exports;

                if !usable[index] {
                    log_line!(
                        "resolve_from_exports",
                        "Could not read exports from loaded \"{}\"; resolving them one by one.",
                        self.v_libraries[index].name
                    );
                }
            }
        }

        for hook in &self.v_all_hooks {
            let hook = unsafe { &mut **hook };
            let Some(&index) = by_name.get(&hook.lib_name()) else {
                log_line!(
                    "resolve_from_exports",
                    "Hook library \"{}\" was not found; skipping.",
                    hook.lib_name()
                );
                continue;
            };

            match Self::resolve_export(&self.v_libraries, &usable, index, &hook.proc_name()) {
                Resolution::Address(address) => {
                    hook.proc_address = address;

                    if address.is_null() {
                        log_line!(
                            "resolve_from_exports",
                            "Could not retrieve ProcAddress for: {} - {}",
                            hook.lib_name(),
                            hook.proc_name()
                        );
                    }
                }
                Resolution::Deferred => {
                    self.v_loader_calls.push(LoaderCall {
                        library: index,
                        proc: hook.proc_name(),
                        hook: hook as *mut Hook,
                        flag: ptr::null(),
                    });
                }
            }
        }

        if !self.v_feature_flags.is_empty() {
            log_line!(
                "resolve_from_exports",
                "Starting feature flags resolution..."
            );
        }

        for index in 0..self.v_feature_flags.len() {
            let flag = self.v_feature_flags[index];
            let symbol = c_array_to_str(&flag.symbol);
            let Some(&library) = by_name.get(&c_array_to_str(&flag.lib)) else {
                log_line!(
                    "resolve_from_exports",
                    "Feature flag library \"{}\" was not found; skipping.",
                    c_array_to_str(&flag.lib)
                );
                continue;
            };

            match Self::resolve_export(&self.v_libraries, &usable, library, &symbol) {
                Resolution::Address(address) => {
                    self.apply_feature_flag(&flag, address)?;
                }
                Resolution::Deferred => {
                    self.v_loader_calls.push(LoaderCall {
                        library,
                        proc: symbol,
                        hook: ptr::null_mut(),
                        flag: &self.v_feature_flags[index],
                    });
                }
            }
        }

        Ok(())
    }

    fn apply_feature_flag(
        &self,
        flag: &FeatureFlagEntry,
        address: *mut c_void,
    ) -> Result<(), LastError> {
        if !address.is_null() {
            let true_value = 1u8;
            if !self.patch_mem(address, &true_value as *const u8 as *const c_void, 1) {
                return Err(throw_memory_error(
                    "WriteProcessMemory",
                    address,
                    1,
                    &self.exe,
                ));
            }

            log_line!(
                "apply_feature_flag",
                "Set feature flag \"{}\" in \"{}\" at 0x{:08X}",
                c_array_to_str(&flag.symbol),
                c_array_to_str(&flag.lib),
                address as usize
            );
        } else {
            log_line!(
                "apply_feature_flag",
                "Feature flag \"{}\" not exported by \"{}\", skipping.",
                c_array_to_str(&flag.symbol),
                c_array_to_str(&flag.lib)
            );
        }

        Ok(())
    }
}

impl SyringeDebugger {
    // -------------------------------------------------------------- DLL scan

    pub fn find_dlls(&mut self) {
        self.breakpoints.clear();
        let mut loaded_dlls = BTreeSet::new();

        for dll in self.dlls.clone() {
            log_line!("find_dlls", "Searching for DLLs matching \"{}\"...", dll);

            let Ok(pattern) = CString::new(dll.as_bytes()) else {
                log_line!(
                    "find_dlls",
                    "Ignoring pattern with an embedded NUL: {:?}",
                    dll
                );
                continue;
            };
            let mut file = FindFile::new(&pattern);

            while file.is_valid() {
                let filename = c_char_array_to_str(&file.data().cFileName);
                file.advance();

                let Ok(mut dll_file) = PortableExecutable::new(&filename) else {
                    continue;
                };

                let mut buffer = HookBuffer::new();

                let mut can_load = if let Some(hooks) = dll_file.find_section(".syhks00") {
                    let hooks = *hooks;
                    self.parse_hooks_section(&mut dll_file, &hooks, &mut buffer)
                } else {
                    Self::parse_inj_file_hooks(&filename, &mut buffer)
                };

                if can_load {
                    log_line!("find_dlls", "Recognized DLL: \"{}\"", filename);

                    if let Some(result) = self.handshake(
                        dll_file.filename(),
                        buffer.count as i32,
                        buffer.checksum.value(),
                    ) {
                        can_load = result;
                    } else if let Some(hosts) = dll_file.find_section(".syexe00") {
                        let hosts = *hosts;
                        can_load = self.can_host_dll(&mut dll_file, &hosts);
                    }
                }

                if can_load {
                    loaded_dlls.insert(filename.clone());
                    for (eip, hooks) in buffer.hooks {
                        let info = self.breakpoints.entry(eip).or_default();
                        info.original_opcode = 0x00;
                        info.hooks.extend(hooks);
                    }
                } else if !buffer.hooks.is_empty() {
                    log_line!("find_dlls", "DLL load was prevented: \"{}\"", filename);
                }
            }
        }

        let mut all_hooks = Vec::new();
        for info in self.breakpoints.values_mut() {
            for hook in &mut info.hooks {
                all_hooks.push(hook as *mut Hook);
            }
        }
        self.v_all_hooks = all_hooks;

        log_line!(
            "find_dlls",
            "Done ({} hooks added).",
            self.v_all_hooks.len()
        );

        self.v_feature_flags.clear();
        self.v_libraries.clear();

        let mut unique_libs = BTreeSet::new();
        for hook in &self.v_all_hooks {
            let hook = unsafe { &**hook };

            if unique_libs.insert(hook.lib_name()) {
                for flag_name in FEATURE_FLAGS {
                    let mut entry = FeatureFlagEntry::default();
                    copy_name(&mut entry.lib, &hook.lib_name());
                    copy_name(&mut entry.symbol, flag_name);
                    self.v_feature_flags.push(entry);
                }

                self.v_libraries.push(HookLibrary {
                    name: hook.lib_name(),
                    exports: HashMap::new(),
                    module: ptr::null_mut(),
                });
            }
        }

        // A recognized DLL with no hooks still needs a LoadLibrary call so its
        // DllMain can run. C++ Syringe only loads hook hosts; this is a small
        // superset that keeps no-hook diagnostic DLLs useful.
        for name in loaded_dlls {
            if !unique_libs.contains(&name) {
                self.v_libraries.push(HookLibrary {
                    name,
                    exports: HashMap::new(),
                    module: ptr::null_mut(),
                });
            }
        }

        log_line!(
            "find_dlls",
            "{} feature flag entries prepared.",
            self.v_feature_flags.len()
        );
        log_line!();
    }
}
