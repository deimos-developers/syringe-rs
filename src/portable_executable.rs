//! Translation of `SyringeEx/PortableExecutable.h` and `PortableExecutable.cpp`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem::zeroed;

use windows_sys::Win32::Foundation::ERROR_BAD_EXE_FORMAT;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_ORDINAL_FLAG32,
};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;

use crate::support::{LastError, throw_lasterror_or};

#[derive(Clone)]
pub struct PEThunkData {
    pub u_thunk_data: IMAGE_THUNK_DATA32,
    pub b_is_ordinal: bool,
    pub address: u32,
    pub ordinal: u32,
    pub name: String,
    pub w_word: u16,
}

impl Default for PEThunkData {
    fn default() -> Self {
        Self {
            u_thunk_data: unsafe { zeroed() },
            b_is_ordinal: false,
            address: 0,
            ordinal: 0,
            name: String::new(),
            w_word: 0,
        }
    }
}

#[derive(Clone)]
pub struct PEImport {
    pub u_desc: IMAGE_IMPORT_DESCRIPTOR,
    pub name: String,
    pub thunks: Vec<PEThunkData>,
}

impl Default for PEImport {
    fn default() -> Self {
        Self {
            u_desc: unsafe { zeroed() },
            name: String::new(),
            thunks: Vec::new(),
        }
    }
}

pub struct PortableExecutable {
    filename: String,
    file: File,
    dos_header: IMAGE_DOS_HEADER,
    pe_header: IMAGE_NT_HEADERS32,
    sections: Vec<IMAGE_SECTION_HEADER>,
    imports: Vec<PEImport>,
}

impl PortableExecutable {
    pub fn new(filename: &str) -> Result<Self, LastError> {
        let file = File::open(filename)
            .map_err(|_| throw_lasterror_or(ERROR_BAD_EXE_FORMAT as u32, filename.to_string()))?;

        let mut this = Self {
            filename: filename.to_string(),
            file,
            dos_header: unsafe { zeroed() },
            pe_header: unsafe { zeroed() },
            sections: Vec::new(),
            imports: Vec::new(),
        };

        if !this.read_file() {
            return Err(throw_lasterror_or(
                ERROR_BAD_EXE_FORMAT as u32,
                filename.to_string(),
            ));
        }

        Ok(this)
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn dos_header(&self) -> &IMAGE_DOS_HEADER {
        &self.dos_header
    }

    pub fn pe_header(&self) -> &IMAGE_NT_HEADERS32 {
        &self.pe_header
    }

    pub fn sections(&self) -> &[IMAGE_SECTION_HEADER] {
        &self.sections
    }

    pub fn imports(&self) -> &[PEImport] {
        &self.imports
    }

    pub fn image_base(&self) -> u32 {
        self.pe_header.OptionalHeader.ImageBase
    }

    pub fn virtual_to_raw(&self, address: u32) -> u32 {
        Self::virtual_to_raw_in(&self.sections, address)
    }

    fn virtual_to_raw_in(sections: &[IMAGE_SECTION_HEADER], address: u32) -> u32 {
        for section in sections {
            let difference = address.wrapping_sub(section.VirtualAddress);

            if difference < section.SizeOfRawData {
                return section.PointerToRawData.wrapping_add(difference);
            }
        }

        0
    }

    pub fn read_bytes(&mut self, raw_address: u32, size: usize, destination: &mut [u8]) -> bool {
        // C++ does `fread(dest, size, 1) == 1`, which is false when size is zero.
        if size == 0 || destination.len() < size {
            return false;
        }

        if self.file.seek(SeekFrom::Start(raw_address as u64)).is_err() {
            return false;
        }

        self.file.read_exact(&mut destination[..size]).is_ok()
    }

    pub fn read_c_string(&mut self, raw_address: u32) -> Option<String> {
        if self.file.seek(SeekFrom::Start(raw_address as u64)).is_err() {
            return None;
        }

        let mut bytes = Vec::with_capacity(0x40);
        let mut byte = [0u8; 1];
        loop {
            match self.file.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) if byte[0] == 0 => break,
                Ok(_) => bytes.push(byte[0]),
            }
            if bytes.len() == 0x100 {
                break;
            }
        }

        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn find_section(&self, name: &str) -> Option<&IMAGE_SECTION_HEADER> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > 8 {
            return None;
        }

        let mut padded = [0u8; 8];
        padded[..bytes.len()].copy_from_slice(bytes);

        self.sections.iter().find(|section| section.Name == padded)
    }

    fn read_file(&mut self) -> bool {
        let file = &mut self.file;
        let _ = file.seek(SeekFrom::Start(0));
        if file
            .read_exact(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut self.dos_header as *mut IMAGE_DOS_HEADER as *mut u8,
                    std::mem::size_of::<IMAGE_DOS_HEADER>(),
                )
            })
            .is_err()
        {
            return false;
        }

        if self.dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }

        if file
            .seek(SeekFrom::Start(self.dos_header.e_lfanew as u64))
            .is_err()
        {
            return false;
        }

        if file
            .read_exact(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut self.pe_header as *mut IMAGE_NT_HEADERS32 as *mut u8,
                    std::mem::size_of::<IMAGE_NT_HEADERS32>(),
                )
            })
            .is_err()
        {
            return false;
        }

        if self.pe_header.Signature != IMAGE_NT_SIGNATURE {
            return false;
        }

        // PE files allow at most 96 sections; reject malformed counts before
        // allocating, so a corrupt header cannot request an enormous Vec.
        let section_count = self.pe_header.FileHeader.NumberOfSections as usize;
        if section_count == 0 || section_count > 96 {
            return false;
        }
        self.sections.clear();
        self.sections.resize(section_count, unsafe { zeroed() });

        for section in &mut self.sections {
            if file
                .read_exact(unsafe {
                    std::slice::from_raw_parts_mut(
                        section as *mut IMAGE_SECTION_HEADER as *mut u8,
                        std::mem::size_of::<IMAGE_SECTION_HEADER>(),
                    )
                })
                .is_err()
            {
                return false;
            }
        }

        let import_directory =
            self.pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        self.imports.clear();
        if import_directory.Size != 0 && import_directory.VirtualAddress != 0 {
            if file
                .seek(SeekFrom::Start(Self::virtual_to_raw_in(
                    &self.sections,
                    import_directory.VirtualAddress,
                ) as u64))
                .is_err()
            {
                return false;
            }

            for _ in 0..0x1000 {
                let mut descriptor: IMAGE_IMPORT_DESCRIPTOR = unsafe { zeroed() };
                if file
                    .read_exact(unsafe {
                        std::slice::from_raw_parts_mut(
                            &mut descriptor as *mut IMAGE_IMPORT_DESCRIPTOR as *mut u8,
                            std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
                        )
                    })
                    .is_err()
                {
                    return false;
                }

                if unsafe { descriptor.Anonymous.Characteristics } == 0 {
                    break;
                }

                self.imports.push(PEImport {
                    u_desc: descriptor,
                    ..Default::default()
                });
            }

            for import in &mut self.imports {
                if file
                    .seek(SeekFrom::Start(Self::virtual_to_raw_in(
                        &self.sections,
                        import.u_desc.Name,
                    ) as u64))
                    .is_err()
                {
                    return false;
                }

                import.name = Self::read_c_line(file).unwrap_or_default();

                if file
                    .seek(SeekFrom::Start(Self::virtual_to_raw_in(
                        &self.sections,
                        import.u_desc.FirstThunk,
                    ) as u64))
                    .is_err()
                {
                    return false;
                }

                for _ in 0..0x1000 {
                    let mut thunk: IMAGE_THUNK_DATA32 = unsafe { zeroed() };
                    if file
                        .read_exact(unsafe {
                            std::slice::from_raw_parts_mut(
                                &mut thunk as *mut IMAGE_THUNK_DATA32 as *mut u8,
                                std::mem::size_of::<IMAGE_THUNK_DATA32>(),
                            )
                        })
                        .is_err()
                    {
                        return false;
                    }

                    if unsafe { thunk.u1.AddressOfData } == 0 {
                        break;
                    }

                    import.thunks.push(PEThunkData {
                        u_thunk_data: thunk,
                        ..Default::default()
                    });
                }

                let first_thunk = import.u_desc.FirstThunk;
                for (index, thunk) in import.thunks.iter_mut().enumerate() {
                    thunk.address =
                        first_thunk.wrapping_add((index as u32).wrapping_mul(std::mem::size_of::<
                            IMAGE_THUNK_DATA32,
                        >(
                        )
                            as u32));

                    let ordinal = unsafe { thunk.u_thunk_data.u1.Ordinal };
                    thunk.b_is_ordinal = (ordinal & IMAGE_ORDINAL_FLAG32) != 0;

                    if thunk.b_is_ordinal {
                        thunk.ordinal = ordinal & 0xFFFF;
                    } else {
                        let name_rva = unsafe { thunk.u_thunk_data.u1.AddressOfData };
                        if file
                            .seek(SeekFrom::Start(
                                Self::virtual_to_raw_in(&self.sections, name_rva) as u64,
                            ))
                            .is_err()
                        {
                            return false;
                        }

                        let mut word = [0u8; 2];
                        if file.read_exact(&mut word).is_err() {
                            return false;
                        }
                        thunk.w_word = u16::from_le_bytes(word);
                        thunk.name = Self::read_c_line(file).unwrap_or_default();
                    }
                }
            }
        }

        true
    }

    fn read_c_line(file: &mut File) -> Option<String> {
        let mut buffer = [0u8; 0x100];
        let mut length = 0usize;

        while length + 1 < buffer.len() {
            let mut byte = [0u8; 1];
            match file.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }

            buffer[length] = byte[0];
            length += 1;

            if byte[0] == b'\n' {
                break;
            }
        }

        buffer[length] = 0;
        let text_length = buffer.iter().position(|&byte| byte == 0).unwrap_or(length);
        Some(String::from_utf8_lossy(&buffer[..text_length]).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::PortableExecutable;

    #[test]
    fn read_bytes_rejects_a_short_destination() {
        let exe = std::env::current_exe().unwrap();
        let mut pe = PortableExecutable::new(exe.to_str().unwrap()).unwrap();
        let mut destination = [0u8; 1];
        assert!(!pe.read_bytes(0, 2, &mut destination));
    }
}
