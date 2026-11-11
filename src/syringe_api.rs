//! Translation of `SyringeEx/include/Syringe.h`.
//!
//! This header is the ABI used by DLLs that Syringe injects. The C++ version
//! relies on macros (`EXPORT`, `DEFINE_HOOK`, `declhook`, ...); the Rust port
//! exposes the same data layouts and helper types. A Rust DLL declares its
//! exports with `#[unsafe(no_mangle)] pub extern "C" fn ...`.

#![allow(non_snake_case)]

use std::mem::size_of;

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

    fn word_data(&self) -> *mut u16 {
        &self.data as *const u32 as *mut u16
    }

    fn byte_data(&self) -> *mut u8 {
        &self.data as *const u32 as *mut u8
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

    fn word_data(&self) -> *mut u16 {
        &self.data as *const u32 as *mut u16
    }

    fn byte_data(&self) -> *mut u8 {
        &self.data as *const u32 as *mut u8
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

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct HookDecl {
    pub hook_addr: u32,
    pub hook_size: u32,
    pub hook_name: *const i8,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct HostDecl {
    pub host_checksum: u32,
    pub host_name: *const i8,
}

#[repr(C)]
pub struct SyringeHandshakeInfo {
    pub cb_size: i32,
    pub num_hooks: i32,
    pub checksum: u32,
    pub exe_filesize: u32,
    pub exe_timestamp: u32,
    pub exe_crc: u32,
    pub cch_message: i32,
    pub message: *mut i8,
}

pub type SyringeHandshakeFunc =
    Option<unsafe extern "C" fn(info: *mut SyringeHandshakeInfo) -> i32>;

#[unsafe(no_mangle)]
pub static mut ESPModification: bool = false;
#[unsafe(no_mangle)]
pub static mut ZFPreservation: bool = false;
#[unsafe(no_mangle)]
pub static mut ReladdrInstructionFixup: bool = false;

// Linker-section declarations used by the C++ `declhook`/`declhost` macros.
pub const HOOKS_SECTION: &str = ".syhks00";
pub const HOSTS_SECTION: &str = ".syexe00";
