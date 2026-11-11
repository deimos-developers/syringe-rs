//! Translation of `SyringeEx/FindFile.h`.

use std::ffi::CStr;
use std::mem::zeroed;

use windows_sys::Win32::Storage::FileSystem::{FindFirstFileA, FindNextFileA, WIN32_FIND_DATAA};

use crate::handle::FindHandle;

pub struct FindFile {
    handle: FindHandle,
    data: WIN32_FIND_DATAA,
}

impl FindFile {
    pub fn new(file_name: &CStr) -> Self {
        let mut data: WIN32_FIND_DATAA = unsafe { zeroed() };
        let handle = unsafe { FindFirstFileA(file_name.as_ptr() as *const u8, &mut data) };

        Self {
            handle: FindHandle::new(handle),
            data,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.handle.is_valid()
    }

    pub fn advance(&mut self) -> &mut Self {
        if self.handle.is_valid()
            && unsafe { FindNextFileA(self.handle.get(), &mut self.data) } == 0
        {
            self.handle.clear();
        }

        self
    }

    pub fn data(&self) -> &WIN32_FIND_DATAA {
        &self.data
    }
}

impl std::ops::Deref for FindFile {
    type Target = WIN32_FIND_DATAA;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
