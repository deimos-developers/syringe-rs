//! Translation of `SyringeEx/Handle.h`.

use std::ffi::c_void;
use std::mem::replace;

use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, HANDLE, HLOCAL, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::FindClose;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};

unsafe extern "C" {
    fn fclose(file: *mut c_void) -> i32;
}

pub trait HandleTraits {
    type Type: Copy + PartialEq;

    fn default_value() -> Self::Type;

    fn close(value: Self::Type);
}

pub struct FileHandleTraits;

impl HandleTraits for FileHandleTraits {
    type Type = *mut c_void;

    fn default_value() -> Self::Type {
        std::ptr::null_mut()
    }

    fn close(file: Self::Type) {
        if !file.is_null() {
            unsafe { fclose(file) };
        }
    }
}

pub struct ThreadHandleTraits;

impl HandleTraits for ThreadHandleTraits {
    type Type = HANDLE;

    fn default_value() -> Self::Type {
        std::ptr::null_mut()
    }

    fn close(handle: Self::Type) {
        if !handle.is_null() {
            unsafe { CloseHandle(handle) };
        }
    }
}

pub struct ModuleHandleTraits;

impl HandleTraits for ModuleHandleTraits {
    type Type = HMODULE;

    fn default_value() -> Self::Type {
        std::ptr::null_mut()
    }

    fn close(handle: Self::Type) {
        if !handle.is_null() {
            unsafe { FreeLibrary(handle) };
        }
    }
}

pub struct FindHandleTraits;

impl HandleTraits for FindHandleTraits {
    type Type = HANDLE;

    fn default_value() -> Self::Type {
        INVALID_HANDLE_VALUE
    }

    fn close(handle: Self::Type) {
        if handle != INVALID_HANDLE_VALUE {
            unsafe { FindClose(handle) };
        }
    }
}

pub struct LocalAllocHandleTraits;

impl HandleTraits for LocalAllocHandleTraits {
    type Type = HLOCAL;

    fn default_value() -> Self::Type {
        std::ptr::null_mut()
    }

    fn close(handle: Self::Type) {
        unsafe { windows_sys::Win32::Foundation::LocalFree(handle) };
    }
}

/// Owns a resource. Not copyable, but movable.
pub struct Handle<Traits: HandleTraits> {
    value: Traits::Type,
}

unsafe impl<Traits: HandleTraits> Send for Handle<Traits> {}

impl<Traits: HandleTraits> Default for Handle<Traits> {
    fn default() -> Self {
        Self {
            value: Traits::default_value(),
        }
    }
}

impl<Traits: HandleTraits> Handle<Traits> {
    pub fn new(value: Traits::Type) -> Self {
        Self { value }
    }

    pub fn is_valid(&self) -> bool {
        self.value != Traits::default_value()
    }

    pub fn get(&self) -> Traits::Type {
        self.value
    }

    pub fn release(&mut self) -> Traits::Type {
        replace(&mut self.value, Traits::default_value())
    }

    pub fn reset(&mut self, value: Traits::Type) {
        self.clear();
        self.value = value;
    }

    pub fn clear(&mut self) {
        let old = self.release();
        Traits::close(old);
    }

    pub fn set(&mut self) -> &mut Traits::Type {
        self.clear();
        &mut self.value
    }

    pub fn swap(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.value, &mut other.value);
    }
}

impl<Traits: HandleTraits> Drop for Handle<Traits> {
    fn drop(&mut self) {
        if self.is_valid() {
            Traits::close(self.value);
        }
    }
}

pub type FileHandle = Handle<FileHandleTraits>;
pub type ThreadHandle = Handle<ThreadHandleTraits>;
pub type ModuleHandle = Handle<ModuleHandleTraits>;
pub type FindHandle = Handle<FindHandleTraits>;
pub type LocalAllocHandle = Handle<LocalAllocHandleTraits>;

#[derive(Default)]
pub struct VirtualMemoryHandle {
    value: *mut c_void,
    process: HANDLE,
}

impl VirtualMemoryHandle {
    pub fn new(process: HANDLE, address: *mut c_void, size: usize) -> Self {
        let mut this = Self {
            value: std::ptr::null_mut(),
            process,
        };

        if !process.is_null() && size != 0 {
            this.value = unsafe {
                VirtualAllocEx(
                    process,
                    address,
                    size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
        }

        this
    }

    pub fn from_allocated(allocated: *mut c_void, process: HANDLE) -> Self {
        Self {
            value: allocated,
            process,
        }
    }

    pub fn get(&self) -> *mut u8 {
        self.value as *mut u8
    }

    pub fn is_valid(&self) -> bool {
        !self.value.is_null()
    }

    pub fn protect(&self, size: usize, protection: PAGE_PROTECTION_FLAGS) -> bool {
        let mut old_protection = 0;
        !self.value.is_null()
            && !self.process.is_null()
            && unsafe {
                VirtualProtectEx(
                    self.process,
                    self.value,
                    size,
                    protection,
                    &mut old_protection,
                ) != 0
            }
    }

    pub fn flush_instruction_cache(&self, size: usize) -> bool {
        !self.value.is_null()
            && !self.process.is_null()
            && unsafe { FlushInstructionCache(self.process, self.value, size) != 0 }
    }

    pub fn clear(&mut self) {
        Self::drop_value(self.value, self.process);
        self.value = std::ptr::null_mut();
        self.process = std::ptr::null_mut();
    }

    pub fn swap(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.value, &mut other.value);
        std::mem::swap(&mut self.process, &mut other.process);
    }

    fn drop_value(value: *mut c_void, process: HANDLE) {
        if !value.is_null() && !process.is_null() {
            unsafe { VirtualFreeEx(process, value, 0, MEM_RELEASE) };
        }
    }
}

impl Drop for VirtualMemoryHandle {
    fn drop(&mut self) {
        Self::drop_value(self.value, self.process);
    }
}
