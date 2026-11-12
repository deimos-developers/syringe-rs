//! Syringe host ABI shared by the loader and hook DLLs.
//!
//! Hook hosts publish a `.syhks00` section of 16-byte [`HookDecl`] records.
//! A loader resolves each `hook_name_ptr` to a raw file offset, reads the
//! export name, and patches `hook_addr` with a jump through the named proc.
//! `.syexe00` sections contain [`HostDecl`] records used by loaders that do
//! not run a handshake.
//!
//! All pointer fields are stored as 32-bit preferred-image-base addresses so
//! the records have the same layout on the Windows target and on hosts used
//! for unit tests. [`SyringeHandshakeInfo`] is only ABI-compatible on a
//! 32-bit target; the loader is a 32-bit Windows binary.

use core::ffi::c_char;
use core::mem::{align_of, offset_of, size_of};

/// Section containing hook declarations in a hook DLL.
pub const HOOKS_SECTION: &str = ".syhks00";
/// Section containing host declarations in a hook DLL.
pub const HOSTS_SECTION: &str = ".syexe00";

/// Feature-flag export names probed by the loader.
pub const FEATURE_FLAGS: [&str; 3] = [
    "ESPModification",
    "ZFPreservation",
    "ReladdrInstructionFixup",
];

/// One `.syhks00` entry. The C++ type is `#pragma pack(16)` and
/// `__declspec(align(16))`, hence the explicit padding attributes.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookDecl {
    /// Address in the target executable to patch.
    pub hook_addr: u32,
    /// Number of bytes the loader must relocate before writing the jump.
    pub hook_size: u32,
    /// Preferred-image-base pointer to the proc export name.
    pub hook_name_ptr: u32,
}

impl HookDecl {
    pub const SIZE: usize = 16;

    pub const fn new(hook_addr: u32, hook_size: u32, hook_name_ptr: u32) -> Self {
        Self {
            hook_addr,
            hook_size,
            hook_name_ptr,
        }
    }

    /// Reconstructs a declaration from the on-disk section bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        // SAFETY: `Self` is `repr(C, align(16))`, all fields are plain `u32`
        // and the source slice is at least `SIZE` bytes.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }

    /// Whether this record names a proc; all-zero padding records are skipped.
    pub fn is_named(&self) -> bool {
        self.hook_name_ptr != 0
    }
}

/// One `.syexe00` entry: executable checksum (currently informational) and a
/// preferred-image-base pointer to the executable base name.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostDecl {
    pub host_checksum: u32,
    pub host_name_ptr: u32,
}

impl HostDecl {
    pub const SIZE: usize = 16;

    pub const fn new(host_checksum: u32, host_name_ptr: u32) -> Self {
        Self {
            host_checksum,
            host_name_ptr,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        // SAFETY: same invariants as `HookDecl::from_bytes`.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }

    pub fn is_named(&self) -> bool {
        self.host_name_ptr != 0
    }
}

/// The C++ `SyringeHandshakeInfo` layout. `message` points to a caller-owned
/// buffer of `cch_message` bytes.
#[repr(C)]
#[derive(Debug)]
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
<<<<<<< HEAD
    /// Creates a handshake record with a null message pointer.
    pub const fn new() -> Self {
        Self {
            cb_size: size_of::<Self>() as i32,
            num_hooks: 0,
            checksum: 0,
            exe_filesize: 0,
            exe_timestamp: 0,
            exe_crc: 0,
            cch_message: 0,
            message: core::ptr::null_mut(),
        }
    }

    /// Attaches a writable message buffer and records its capacity in bytes.
    pub fn with_message_buffer(&mut self, buffer: &mut [u8]) -> &mut Self {
        self.cch_message = buffer.len().min(i32::MAX as usize) as i32;
        self.message = buffer.as_mut_ptr().cast::<c_char>();
        self
    }
}

impl Default for SyringeHandshakeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature of a hook proc; returning `0` continues, anything else is the
/// next instruction pointer.
pub type HookProc = unsafe extern "C" fn(registers: *mut core::ffi::c_void) -> u32;

const _: () = {
    assert!(HookDecl::SIZE == size_of::<HookDecl>());
    assert!(HostDecl::SIZE == size_of::<HostDecl>());
    assert!(align_of::<HookDecl>() == 16);
    assert!(align_of::<HostDecl>() == 16);
    assert!(offset_of!(HookDecl, hook_name_ptr) == 8);
    assert!(offset_of!(HostDecl, host_name_ptr) == 4);
    #[cfg(target_pointer_width = "32")]
    {
        assert!(size_of::<SyringeHandshakeInfo>() == 32);
        assert!(offset_of!(SyringeHandshakeInfo, message) == 28);
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_decl_layout_matches_the_syringe_abi() {
        assert_eq!(size_of::<HookDecl>(), 16);
        assert_eq!(align_of::<HookDecl>(), 16);
        assert_eq!(offset_of!(HookDecl, hook_addr), 0);
        assert_eq!(offset_of!(HookDecl, hook_size), 4);
        assert_eq!(offset_of!(HookDecl, hook_name_ptr), 8);
    }

    #[test]
    fn host_decl_layout_matches_the_syringe_abi() {
        assert_eq!(size_of::<HostDecl>(), 16);
        assert_eq!(align_of::<HostDecl>(), 16);
        assert_eq!(offset_of!(HostDecl, host_checksum), 0);
        assert_eq!(offset_of!(HostDecl, host_name_ptr), 4);
    }

    #[test]
    fn hook_decl_round_trips_and_skips_padding() {
        let bytes = [
            0x83, 0x45, 0x4F, 0x00, // 0x4F4583
            0x06, 0x00, 0x00, 0x00, // 6 bytes
            0x00, 0x04, 0x40, 0x10, // 0x10400400
            0, 0, 0, 0, // alignment padding
        ];
        let decl = HookDecl::from_bytes(&bytes).unwrap();
        assert_eq!(decl, HookDecl::new(0x004F_4583, 6, 0x1040_0400));
        assert!(decl.is_named());
        assert!(!HookDecl::default().is_named());
    }

    #[test]
    fn short_or_missing_declarations_are_rejected() {
        assert!(HookDecl::from_bytes(&[0; 15]).is_none());
        assert!(HostDecl::from_bytes(&[0; 15]).is_none());
        assert!(!HookDecl::from_bytes(&[0; 16]).unwrap().is_named());
    }

    #[test]
    fn host_decl_round_trips() {
        let bytes = [
            0x00, 0x00, 0x00, 0x00, // checksum
            0x21, 0x04, 0x40, 0x10, // name pointer
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let decl = HostDecl::from_bytes(&bytes).unwrap();
        assert_eq!(decl, HostDecl::new(0, 0x1040_0421));
        assert!(decl.is_named());
    }

    #[test]
    fn handshake_buffer_is_recorded() {
        let mut info = SyringeHandshakeInfo::new();
        let mut buffer = [0u8; 0x100];
        info.with_message_buffer(&mut buffer);
        assert_eq!(info.cch_message, 0x100);
        assert_eq!(info.message, buffer.as_mut_ptr().cast());
        assert_eq!(info.cb_size, size_of::<SyringeHandshakeInfo>() as i32);
    }

    #[test]
    fn feature_flags_match_the_loader_contract() {
        assert_eq!(
            FEATURE_FLAGS,
            [
                "ESPModification",
                "ZFPreservation",
                "ReladdrInstructionFixup"
            ]
        );
    }
=======
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
>>>>>>> ec8d38839eaeb20a13a05de201f5521f1a74d862
}
