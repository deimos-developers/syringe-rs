//! Rust bindings for SyringeEx's public ABI (`SyringeEx/include/Syringe.h`).
//!
//! A Syringe hook host is a DLL with a `.syhks00` section. Every 16-byte
//! [`HookDecl`] in that section names a hook address, the number of bytes the
//! loader must relocate and the PE export name of the proc to call:
//!
//! ```text
//! hook_addr   u32   virtual address in the target executable
//! hook_size   u32   bytes overwritten by the loader's jump
//! hook_name   ptr   preferred-image-base pointer to "ProcName\0"
//! ```
//!
//! The proc has the [`HookProc`] signature (`cdecl`, one `*mut Registers`
//! argument). Returning `0` continues the hooked code; any other value is
//! used as the new `EIP`. The loader saves the x86 register file in the
//! layout of [`Registers`], so [`Registers::origin`] is the hook address and
//! the general-purpose registers can be read or modified before continuing.
//!
//! The [`declhook!`], [`declhook_again!`], [`declhost!`] and [`define_hook!`]
//! macros mirror the C++ `declhook` / `DEFINE_HOOK_AGAIN` / `declhost` /
//! `DEFINE_HOOK` macros. The hook name is the proc's export name, so a proc
//! used from two hook addresses needs two declarations (`declhook_again!`)
//! but only one function.
//!
//! The optional `SyringeHandshake` export receives a [`SyringeHandshakeInfo`]
//! and can reject the host. The optional `ESPModification`, `ZFPreservation`
//! and `ReladdrInstructionFixup` exports are set to `1` by the loader when it
//! supports the corresponding feature.

#![allow(non_snake_case)]

use core::ffi::c_char;
use core::mem::size_of;

mod sealed {
    pub trait Sealed {}
}

/// Types whose every bit pattern is valid and which fit in one x86 register.
///
/// This is sealed: `get::<bool>()`, `get::<char>()` or references cannot be
/// requested through the safe register helpers.
pub trait RegisterValue: Copy + sealed::Sealed {}

impl<T: Copy + sealed::Sealed> RegisterValue for T {}

macro_rules! impl_register_value {
    ($($ty:ty),* $(,)?) => {
        $(impl sealed::Sealed for $ty {})*
    };
}

impl_register_value!(u8, u16, u32, i8, i16, i32, f32, usize, isize);

impl<T> sealed::Sealed for *const T {}
impl<T> sealed::Sealed for *mut T {}

fn read_register<T: RegisterValue>(data: u32) -> T {
    assert!(size_of::<T>() <= size_of::<u32>());
    // SAFETY: `RegisterValue` is sealed to scalar and raw-pointer types, all
    // of whose bit patterns are valid; the size assertion keeps the read in
    // bounds of the 32-bit register.
    unsafe { std::ptr::read_unaligned(&data as *const u32 as *const T) }
}

/// Converts values to the 32-bit register representation used by the C++
/// `DWORD(value)` casts.
pub trait ToDword {
    fn to_dword(self) -> u32;
}

impl ToDword for u8 {
    fn to_dword(self) -> u32 {
        self as u32
    }
}

impl ToDword for u16 {
    fn to_dword(self) -> u32 {
        self as u32
    }
}

impl ToDword for u32 {
    fn to_dword(self) -> u32 {
        self
    }
}

impl ToDword for i32 {
    fn to_dword(self) -> u32 {
        self as u32
    }
}

impl ToDword for usize {
    fn to_dword(self) -> u32 {
        self as u32
    }
}

impl<T> ToDword for *const T {
    fn to_dword(self) -> u32 {
        self as usize as u32
    }
}

impl<T> ToDword for *mut T {
    fn to_dword(self) -> u32 {
        self as usize as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LimitedRegister {
    data: u32,
}

impl LimitedRegister {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> u32 {
        self.data
    }

    pub fn set_data(&mut self, value: u32) {
        self.data = value;
    }

    pub fn get16(&self) -> u16 {
        self.data as u16
    }

    pub fn set16(&mut self, value: u16) {
        self.data = (self.data & 0xFFFF_0000) | value as u32;
    }

    pub fn get<T: RegisterValue>(&self) -> T {
        read_register(self.data)
    }

    pub fn set<T: ToDword>(&mut self, value: T) {
        self.data = value.to_dword();
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExtendedRegister {
    data: u32,
}

impl ExtendedRegister {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> u32 {
        self.data
    }

    pub fn set_data(&mut self, value: u32) {
        self.data = value;
    }

    pub fn get8_hi(&self) -> u8 {
        (self.data >> 8) as u8
    }

    pub fn get8_lo(&self) -> u8 {
        self.data as u8
    }

    pub fn set8_hi(&mut self, value: u8) {
        self.data = (self.data & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn set8_lo(&mut self, value: u8) {
        self.data = (self.data & 0xFFFF_FF00) | value as u32;
    }

    // Inherited from LimitedRegister in C++.
    pub fn get16(&self) -> u16 {
        self.data as u16
    }

    pub fn set16(&mut self, value: u16) {
        self.data = (self.data & 0xFFFF_0000) | value as u32;
    }

    pub fn get<T: RegisterValue>(&self) -> T {
        read_register(self.data)
    }

    pub fn set<T: ToDword>(&mut self, value: T) {
        self.data = value.to_dword();
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StackRegister {
    data: u32,
}

impl StackRegister {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> u32 {
        self.data
    }

    pub fn set_data(&mut self, value: u32) {
        self.data = value;
    }

    /// C++ `lea(int)` returning a `DWORD` offset.
    pub fn lea(&self, offset: i32) -> u32 {
        self.data.wrapping_add(offset as u32)
    }

    /// C++ `template<typename T> T* lea(int)`.
    pub fn lea_as<T>(&self, offset: i32) -> *mut T {
        self.lea(offset) as usize as *mut T
    }

    /// # Safety
    /// `self.data + offset` must point to a readable `T`.
    pub unsafe fn at<T: RegisterValue>(&self, offset: i32) -> T {
        // SAFETY: guaranteed by the caller.
        unsafe { std::ptr::read_unaligned(self.lea_as::<T>(offset)) }
    }

    /// # Safety
    /// `self.data + offset` must point to a writable `T`.
    pub unsafe fn set_at<T: RegisterValue>(&mut self, offset: i32, value: T) {
        // SAFETY: guaranteed by the caller.
        unsafe { std::ptr::write_unaligned(self.lea_as::<T>(offset), value) };
    }

    /// # Safety
    /// `self.data + offset` must point to a readable `u32`.
    pub unsafe fn at_u32(&self, offset: i32) -> u32 {
        // SAFETY: guaranteed by the caller.
        unsafe { self.at(offset) }
    }

    /// # Safety
    /// `self.data + offset` must point to a writable `u32`.
    pub unsafe fn set_at_u32(&mut self, offset: i32, value: u32) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.set_at(offset, value) };
    }

    // Inherited from LimitedRegister / ExtendedRegister in C++.
    pub fn get16(&self) -> u16 {
        self.data as u16
    }

    pub fn set16(&mut self, value: u16) {
        self.data = (self.data & 0xFFFF_0000) | value as u32;
    }

    pub fn get<T: RegisterValue>(&self) -> T {
        read_register(self.data)
    }

    pub fn set<T: ToDword>(&mut self, value: T) {
        self.data = value.to_dword();
    }

    pub fn get8_hi(&self) -> u8 {
        (self.data >> 8) as u8
    }

    pub fn get8_lo(&self) -> u8 {
        self.data as u8
    }

    pub fn set8_hi(&mut self, value: u8) {
        self.data = (self.data & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn set8_lo(&mut self, value: u8) {
        self.data = (self.data & 0xFFFF_FF00) | value as u32;
    }
}

macro_rules! register_accessors {
    ($get:ident, $set:ident, $as:ident, $set_as:ident, $field:ident) => {
        pub fn $get(&self) -> u32 {
            self.$field
        }

        pub fn $set(&mut self, value: u32) {
            self.$field = value;
        }

        pub fn $as<T: RegisterValue>(&self) -> T {
            read_register(self.$field)
        }

        pub fn $set_as<T: ToDword>(&mut self, value: T) {
            self.$field = value.to_dword();
        }
    };
}

/// C++ `REGISTERS`; layout is two DWORDs followed by the eight x86 registers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Registers {
    origin: u32,
    flags: u32,
    edi: u32,
    esi: u32,
    ebp: StackRegister,
    esp: StackRegister,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
}

impl Registers {
    /// A zeroed register file, matching a cleared `REGISTERS` in C++.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn origin(&self) -> u32 {
        self.origin
    }

    pub fn set_origin(&mut self, value: u32) {
        self.origin = value;
    }

    pub fn eflags(&self) -> u32 {
        self.flags
    }

    pub fn set_eflags(&mut self, value: u32) {
        self.flags = value;
    }

    register_accessors!(edi, set_edi, edi_as, set_edi_as, edi);
    register_accessors!(esi, set_esi, esi_as, set_esi_as, esi);
    register_accessors!(ebx, set_ebx, ebx_as, set_ebx_as, ebx);
    register_accessors!(edx, set_edx, edx_as, set_edx_as, edx);
    register_accessors!(ecx, set_ecx, ecx_as, set_ecx_as, ecx);
    register_accessors!(eax, set_eax, eax_as, set_eax_as, eax);

    // C++ `REG_SHORTCUTS(EBP)` / `REG_SHORTCUTS(ESP)` return the DWORD value
    // and provide a template overload. The underlying StackRegister is exposed
    // separately so its `lea`/`at` helpers remain usable.
    pub fn ebp(&self) -> u32 {
        self.ebp.data()
    }

    pub fn set_ebp(&mut self, value: u32) {
        self.ebp.set_data(value);
    }

    pub fn ebp_as<T: RegisterValue>(&self) -> T {
        self.ebp.get()
    }

    pub fn set_ebp_as<T: ToDword>(&mut self, value: T) {
        self.ebp.set(value);
    }

    pub fn ebp_register(&self) -> &StackRegister {
        &self.ebp
    }

    pub fn ebp_register_mut(&mut self) -> &mut StackRegister {
        &mut self.ebp
    }

    pub fn esp(&self) -> u32 {
        self.esp.data()
    }

    pub fn set_esp(&mut self, value: u32) {
        self.esp.set_data(value);
    }

    pub fn esp_as<T: RegisterValue>(&self) -> T {
        self.esp.get()
    }

    pub fn set_esp_as<T: ToDword>(&mut self, value: T) {
        self.esp.set(value);
    }

    pub fn esp_register(&self) -> &StackRegister {
        &self.esp
    }

    pub fn esp_register_mut(&mut self) -> &mut StackRegister {
        &mut self.esp
    }

    /// C++ `template<typename T> T lea_Stack(int)`: reinterprets the 32-bit
    /// stack address as `T`. Only pointer-sized or 32-bit integral `T` is valid
    /// in the original C++ as well.
    pub fn lea_stack<T: RegisterValue>(&self, offset: i32) -> T {
        assert_eq!(size_of::<T>(), size_of::<u32>());
        unsafe { std::mem::transmute_copy(&self.esp.lea(offset)) }
    }

    pub fn lea_stack_u32(&self, offset: i32) -> u32 {
        self.esp.lea(offset)
    }

    /// # Safety
    /// The stack address plus `offset` must point to a live `T`.
    pub unsafe fn ref_stack<T: RegisterValue>(&mut self, offset: i32) -> &mut T {
        // SAFETY: guaranteed by the caller.
        unsafe { &mut *self.esp.lea_as::<T>(offset) }
    }

    /// # Safety
    /// The stack address plus `offset` must point to a readable `T`.
    pub unsafe fn stack<T: RegisterValue>(&self, offset: i32) -> T {
        // SAFETY: guaranteed by the caller.
        unsafe { self.esp.at(offset) }
    }

    /// # Safety
    /// The stack address plus `offset` must point to a writable `T`.
    pub unsafe fn set_stack<T: RegisterValue>(&mut self, offset: i32, value: T) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.esp.set_at(offset, value) };
    }

    /// # Safety
    /// The stack address plus `offset` must point to a readable `u32`.
    pub unsafe fn stack32(&self, offset: i32) -> u32 {
        // SAFETY: guaranteed by the caller.
        unsafe { self.stack(offset) }
    }

    /// # Safety
    /// The stack address plus `offset` must point to a writable `u32`.
    pub unsafe fn set_stack32(&mut self, offset: i32, value: u32) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.set_stack(offset, value) };
    }

    /// # Safety
    /// The stack address plus `offset` must point to a readable `u16`.
    pub unsafe fn stack16(&self, offset: i32) -> u16 {
        // SAFETY: guaranteed by the caller.
        unsafe { self.stack(offset) }
    }

    /// # Safety
    /// The stack address plus `offset` must point to a writable `u16`.
    pub unsafe fn set_stack16(&mut self, offset: i32, value: u16) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.set_stack(offset, value) };
    }

    /// # Safety
    /// The stack address plus `offset` must point to a readable `u8`.
    pub unsafe fn stack8(&self, offset: i32) -> u8 {
        // SAFETY: guaranteed by the caller.
        unsafe { self.stack(offset) }
    }

    /// # Safety
    /// The stack address plus `offset` must point to a writable `u8`.
    pub unsafe fn set_stack8(&mut self, offset: i32, value: u8) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.set_stack(offset, value) };
    }

    /// # Safety
    /// The base pointer plus `offset` must point to a readable `T`.
    pub unsafe fn base<T: RegisterValue>(&self, offset: i32) -> T {
        // SAFETY: guaranteed by the caller.
        unsafe { self.ebp.at(offset) }
    }

    /// # Safety
    /// The base pointer plus `offset` must point to a writable `T`.
    pub unsafe fn set_base<T: RegisterValue>(&mut self, offset: i32, value: T) {
        // SAFETY: guaranteed by the caller.
        unsafe { self.ebp.set_at(offset, value) };
    }

    // XHL shortcuts: AX/AH/AL, BX/BH/BL, CX/CH/CL, DX/DH/DL.
    pub fn ax(&self) -> u16 {
        self.eax as u16
    }

    pub fn set_ax(&mut self, value: u16) {
        self.eax = (self.eax & 0xFFFF_0000) | value as u32;
    }

    pub fn ah(&self) -> u8 {
        (self.eax >> 8) as u8
    }

    pub fn set_ah(&mut self, value: u8) {
        self.eax = (self.eax & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn al(&self) -> u8 {
        self.eax as u8
    }

    pub fn set_al(&mut self, value: u8) {
        self.eax = (self.eax & 0xFFFF_FF00) | value as u32;
    }

    pub fn bx(&self) -> u16 {
        self.ebx as u16
    }

    pub fn set_bx(&mut self, value: u16) {
        self.ebx = (self.ebx & 0xFFFF_0000) | value as u32;
    }

    pub fn bh(&self) -> u8 {
        (self.ebx >> 8) as u8
    }

    pub fn set_bh(&mut self, value: u8) {
        self.ebx = (self.ebx & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn bl(&self) -> u8 {
        self.ebx as u8
    }

    pub fn set_bl(&mut self, value: u8) {
        self.ebx = (self.ebx & 0xFFFF_FF00) | value as u32;
    }

    pub fn cx(&self) -> u16 {
        self.ecx as u16
    }

    pub fn set_cx(&mut self, value: u16) {
        self.ecx = (self.ecx & 0xFFFF_0000) | value as u32;
    }

    pub fn ch(&self) -> u8 {
        (self.ecx >> 8) as u8
    }

    pub fn set_ch(&mut self, value: u8) {
        self.ecx = (self.ecx & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn cl(&self) -> u8 {
        self.ecx as u8
    }

    pub fn set_cl(&mut self, value: u8) {
        self.ecx = (self.ecx & 0xFFFF_FF00) | value as u32;
    }

    pub fn dx(&self) -> u16 {
        self.edx as u16
    }

    pub fn set_dx(&mut self, value: u16) {
        self.edx = (self.edx & 0xFFFF_0000) | value as u32;
    }

    pub fn dh(&self) -> u8 {
        (self.edx >> 8) as u8
    }

    pub fn set_dh(&mut self, value: u8) {
        self.edx = (self.edx & 0xFFFF_00FF) | ((value as u32) << 8);
    }

    pub fn dl(&self) -> u8 {
        self.edx as u8
    }

    pub fn set_dl(&mut self, value: u8) {
        self.edx = (self.edx & 0xFFFF_FF00) | value as u32;
    }
}

// The C++ header exposes separate `DWORD` and template getters. The Rust
// accessors above use explicit `_as` names to avoid return-type overloading.

// ---------------------------------------------------------------------------
// Hooks, hosts and the handshake
// ---------------------------------------------------------------------------

/// The ABI of a hook proc.
///
/// The loader calls the proc with `cdecl` and a pointer to the saved
/// [`Registers`]. Returning `0` resumes the hooked code (the loader executes
/// the relocated original instructions and jumps back); returning a non-zero
/// value sets `EIP` to that value instead.
pub type HookProc = unsafe extern "C" fn(registers: *mut Registers) -> u32;

/// One entry of the `.syhks00` section (C++ `hookdecl`).
///
/// `hook_name` must point to a NUL-terminated string containing the export
/// name of the hook proc; the loader resolves the proc by that name.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct HookDecl {
    pub hook_addr: u32,
    pub hook_size: u32,
    pub hook_name: *const c_char,
}

impl HookDecl {
    pub const fn new(hook_addr: u32, hook_size: u32, hook_name: *const c_char) -> Self {
        Self {
            hook_addr,
            hook_size,
            hook_name,
        }
    }
}

// SAFETY: declarations are immutable; the loader only reads them.
unsafe impl Sync for HookDecl {}

/// One entry of the `.syexe00` section (C++ `hostdecl`).
///
/// The loader compares `host_name` plus `".exe"` with the running executable
/// when a DLL does not provide a handshake result.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct HostDecl {
    pub host_checksum: u32,
    pub host_name: *const c_char,
}

impl HostDecl {
    pub const fn new(host_checksum: u32, host_name: *const c_char) -> Self {
        Self {
            host_checksum,
            host_name,
        }
    }
}

// SAFETY: declarations are immutable; the loader only reads them.
unsafe impl Sync for HostDecl {}

/// C++ `SyringeHandshakeInfo`, passed to the optional `SyringeHandshake`
/// export when the loader runs with `--handshakes`.
#[repr(C)]
pub struct SyringeHandshakeInfo {
    pub cb_size: i32,
    pub num_hooks: i32,
    pub checksum: u32,
    pub exe_filesize: u32,
    pub exe_timestamp: u32,
    pub exe_crc: u32,
    pub cch_message: i32,
    pub message: *mut c_char,
}

impl SyringeHandshakeInfo {
    /// Number of writable bytes in [`Self::message`], zero if there is no
    /// buffer. `cch_message` includes the terminating NUL.
    pub fn message_capacity(&self) -> usize {
        if self.cch_message <= 0 || self.message.is_null() {
            0
        } else {
            self.cch_message as usize
        }
    }

    /// Copies `message` (truncated to fit) and a NUL terminator into the
    /// loader-provided buffer.
    ///
    /// # Safety
    ///
    /// If [`Self::message`] is non-null it must point to at least
    /// [`Self::cch_message`] writable bytes.
    pub unsafe fn write_message(&mut self, message: &str) {
        let capacity = self.message_capacity();
        if capacity == 0 {
            return;
        }
        let bytes = message.as_bytes();
        let length = bytes.len().min(capacity - 1);
        // SAFETY: the caller guarantees the buffer size; `length < capacity`.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.message.cast::<u8>(), length);
            self.message.add(length).write(0);
        }
    }
}

/// The signature of the optional `SyringeHandshake` export.
pub type SyringeHandshakeFunc =
    Option<unsafe extern "C" fn(info: *mut SyringeHandshakeInfo) -> i32>;

/// Feature flags queried by the loader. `syringe-rs` writes `1` into every
/// exported flag it finds; the exports are optional.
#[unsafe(no_mangle)]
pub static mut ESPModification: bool = false;
#[unsafe(no_mangle)]
pub static mut ZFPreservation: bool = false;
#[unsafe(no_mangle)]
pub static mut ReladdrInstructionFixup: bool = false;

/// Name of the section holding [`HookDecl`] entries.
pub const HOOKS_SECTION: &str = ".syhks00";
/// Name of the section holding [`HostDecl`] entries.
pub const HOSTS_SECTION: &str = ".syexe00";

// Layout checks against the C++ definitions. `Registers` must be exactly the
// stack image built by the loader's `pushad; pushfd; push site; push esp`.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<LimitedRegister>() == 4);
    assert!(size_of::<ExtendedRegister>() == 4);
    assert!(size_of::<StackRegister>() == 4);
    assert!(size_of::<Registers>() == 40);
    assert!(offset_of!(Registers, origin) == 0);
    assert!(offset_of!(Registers, flags) == 4);
    assert!(offset_of!(Registers, edi) == 8);
    assert!(offset_of!(Registers, esi) == 12);
    assert!(offset_of!(Registers, ebp) == 16);
    assert!(offset_of!(Registers, esp) == 20);
    assert!(offset_of!(Registers, ebx) == 24);
    assert!(offset_of!(Registers, edx) == 28);
    assert!(offset_of!(Registers, ecx) == 32);
    assert!(offset_of!(Registers, eax) == 36);

    assert!(size_of::<HookDecl>() == 16);
    assert!(align_of::<HookDecl>() == 16);
    assert!(offset_of!(HookDecl, hook_addr) == 0);
    assert!(offset_of!(HookDecl, hook_size) == 4);
    assert!(offset_of!(HookDecl, hook_name) == 8);

    assert!(size_of::<HostDecl>() == 16);
    assert!(align_of::<HostDecl>() == 16);
    assert!(offset_of!(HostDecl, host_checksum) == 0);
};

#[cfg(target_pointer_width = "32")]
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SyringeHandshakeInfo>() == 32);
    assert!(offset_of!(SyringeHandshakeInfo, message) == 28);
    assert!(offset_of!(HostDecl, host_name) == 4);
};

// ---------------------------------------------------------------------------
// Macros mirroring Syringe.h
// ---------------------------------------------------------------------------

/// Declares a hook: emits one [`HookDecl`] into `.syhks00`.
///
/// `func` must be the name of an exported hook proc with the [`HookProc`]
/// signature. `hook` must be a literal address (it is stringified into the
/// static's symbol name).
///
/// ```ignore
/// #[unsafe(no_mangle)]
/// pub extern "C" fn MyHook(regs: *mut deimos::syringe_api::Registers) -> u32 {
///     // ...
///     0
/// }
/// deimos::declhook!(0x4F4583, MyHook, 6);
/// ```
#[macro_export]
macro_rules! declhook {
    ($hook:expr, $func:ident, $size:expr) => {
        const _: () = {
            #[used]
            #[allow(dead_code)]
            #[unsafe(export_name = concat!("deimos_hook_decl_", stringify!($hook), "_", stringify!($func)))]
            #[unsafe(link_section = ".syhks00")]
            static HOOK_DECL: $crate::syringe_api::HookDecl = $crate::syringe_api::HookDecl::new(
                $hook,
                $size,
                concat!(stringify!($func), "\0").as_ptr() as *const ::core::ffi::c_char,
            );
        };
    };
}

/// C++ `DEFINE_HOOK_AGAIN`: a second hook declaration for the same proc.
#[macro_export]
macro_rules! declhook_again {
    ($hook:expr, $func:ident, $size:expr) => {
        $crate::declhook!($hook, $func, $size);
    };
}

/// C++ `declhost`: declares which executable this DLL can extend.
///
/// The loader compares `name + ".exe"` with the running executable, so pass
/// the executable name without the extension.
#[macro_export]
macro_rules! declhost {
    ($exe:ident, $checksum:expr) => {
        const _: () = {
            #[used]
            #[allow(dead_code)]
            #[unsafe(export_name = concat!("deimos_host_decl_", stringify!($exe)))]
            #[unsafe(link_section = ".syexe00")]
            static HOST_DECL: $crate::syringe_api::HostDecl = $crate::syringe_api::HostDecl::new(
                $checksum,
                concat!(stringify!($exe), "\0").as_ptr() as *const ::core::ffi::c_char,
            );
        };
    };
}

/// Declares a hook and defines its exported proc in one step.
///
/// ```ignore
/// deimos::define_hook!(0x4F4583, MyHook, 6, |regs| {
///     // `regs` is *mut deimos::syringe_api::Registers
///     0
/// });
/// ```
#[macro_export]
macro_rules! define_hook {
    ($hook:expr, $func:ident, $size:expr, |$regs:ident| $body:block) => {
        $crate::declhook!($hook, $func, $size);

        #[unsafe(no_mangle)]
        pub extern "C" fn $func($regs: *mut $crate::syringe_api::Registers) -> u32 $body
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::define_hook!(0x0045_6789, DeimosTestHook, 5, |_registers| { 0 });

    #[test]
    fn define_hook_macro_declares_and_exports_the_proc() {
        let hook: HookProc = DeimosTestHook;
        assert_ne!(hook as usize, 0);
    }

    #[test]
    fn register_layout_is_syringe_compatible() {
        assert_eq!(core::mem::size_of::<Registers>(), 40);
        assert_eq!(core::mem::offset_of!(Registers, origin), 0);
        assert_eq!(core::mem::offset_of!(Registers, flags), 4);
        assert_eq!(core::mem::offset_of!(Registers, edi), 8);
        assert_eq!(core::mem::offset_of!(Registers, esi), 12);
        assert_eq!(core::mem::offset_of!(Registers, ebp), 16);
        assert_eq!(core::mem::offset_of!(Registers, esp), 20);
        assert_eq!(core::mem::offset_of!(Registers, ebx), 24);
        assert_eq!(core::mem::offset_of!(Registers, edx), 28);
        assert_eq!(core::mem::offset_of!(Registers, ecx), 32);
        assert_eq!(core::mem::offset_of!(Registers, eax), 36);
    }

    #[test]
    fn limited_register_set16_preserves_high_half() {
        let mut register = LimitedRegister::new();
        register.set_data(0x1234_5678);
        assert_eq!(register.get16(), 0x5678);
        register.set16(0xABCD);
        assert_eq!(register.data(), 0x1234_ABCD);
    }

    #[test]
    fn extended_register_halves() {
        let mut register = ExtendedRegister::new();
        register.set_data(0x1234_5678);
        assert_eq!(register.get8_hi(), 0x56);
        assert_eq!(register.get8_lo(), 0x78);
        register.set8_hi(0xAB);
        assert_eq!(register.data(), 0x1234_AB78);
        register.set8_lo(0xCD);
        assert_eq!(register.data(), 0x1234_ABCD);
    }

    #[test]
    fn register_set_zero_extends() {
        let mut register = LimitedRegister::new();
        register.set_data(0xFFFF_FFFF);
        register.set::<u16>(0x1234);
        assert_eq!(register.data(), 0x1234);
    }

    #[test]
    fn stack_register_lea_wraps() {
        let mut register = StackRegister::new();
        register.set_data(0xFFFF_FFF0);
        assert_eq!(register.lea(0x20), 0x10);
        assert_eq!(register.lea(-0x10), 0xFFFF_FFE0);
    }

    #[test]
    fn registers_shortcuts() {
        let mut registers = Registers::new();
        registers.set_eax(0x1234_5678);
        assert_eq!(registers.eax(), 0x1234_5678);
        assert_eq!(registers.ax(), 0x5678);
        assert_eq!(registers.ah(), 0x56);
        assert_eq!(registers.al(), 0x78);
        registers.set_al(0xAB);
        assert_eq!(registers.eax(), 0x1234_56AB);
        registers.set_ah(0xCD);
        assert_eq!(registers.eax(), 0x1234_CDAB);
        registers.set_ax(0x4321);
        assert_eq!(registers.eax(), 0x1234_4321);
    }

    #[test]
    fn hook_decl_layout() {
        let name = b"MyHook\0";
        let decl = HookDecl::new(0x004F_4583, 6, name.as_ptr().cast::<c_char>());
        assert_eq!(core::mem::size_of::<HookDecl>(), 16);
        assert_eq!(decl.hook_addr, 0x004F_4583);
        assert_eq!(decl.hook_size, 6);
        assert_eq!(
            unsafe { core::ffi::CStr::from_ptr(decl.hook_name) }.to_bytes(),
            b"MyHook"
        );
    }

    #[test]
    fn handshake_message_truncates_and_terminates() {
        let mut buffer = [0xFFu8; 8];
        let mut info = SyringeHandshakeInfo {
            cb_size: 0,
            num_hooks: 0,
            checksum: 0,
            exe_filesize: 0,
            exe_timestamp: 0,
            exe_crc: 0,
            cch_message: buffer.len() as i32,
            message: buffer.as_mut_ptr().cast::<c_char>(),
        };
        unsafe { info.write_message("deimos") };
        assert_eq!(&buffer[..7], b"deimos\0");
        assert_eq!(buffer[7], 0xFF);

        unsafe { info.write_message("too long!") };
        assert_eq!(&buffer[..8], b"too lon\0");

        info.cch_message = 0;
        unsafe { info.write_message("ignored") };
        assert_eq!(&buffer[..8], b"too lon\0");
    }
}
