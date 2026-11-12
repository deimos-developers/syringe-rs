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
}
