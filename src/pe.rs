//! Contains functionality for parsing MZ/PE files
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use zerocopy::{AsBytes, FromBytes};

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct MZHeader {
    pub signature: [u8; 2],
    pub last_page_bytes: u16,
    pub num_pages: u16,
    pub num_relocations: u16,
    pub header_size: u16,
    pub min_memory: u16,
    pub max_memory: u16,
    pub initial_ss: u16,
    pub initial_sp: u16,
    pub checksum: u16,
    pub entry: u32,
    pub ptr_relocation: u16,
    pub overlay: u16,
    pub reserved: [u8; 32],
    pub new_header: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct PEHeader {
    pub signature: [u8; 4],
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub ptr_symtable: u32,
    pub num_smtable: u32,
    pub optional_header_size: u16,
    pub characteristics: u16,
}

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct WindowsPEHeader32 {
    pub magic: u16,
    pub linker_major_version: u8,
    pub linker_minor_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub entry: u32,
    pub code_base: u32,
    pub data_base: u32,
    pub image_base: u32,
    pub section_align: u32,
    pub file_align: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub num_tables: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct WindowsPEHeader64 {
    pub magic: u16,
    pub linker_major_version: u8,
    pub linker_minor_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub entry: u32,
    pub code_base: u32,
    pub image_base: u64,
    pub section_align: u32,
    pub file_align: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub num_tables: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct ImageDataDirectory {
    pub vaddr: u32,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub vsize: u32,
    pub vaddr: u32,
    pub raw_data_size: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub timestamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub typ: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, AsBytes, FromBytes)]
pub struct CodeviewEntry {
    pub signature: [u8; 4], // RSDS
    pub guid_a: u32,
    pub guid_b: u16,
    pub guid_c: u16,
    pub guid_d: [u8; 8],
    pub age: u32,
}

pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

/// Read a structure from a file stream, directly interpreting the raw bytes
/// of the file as T.
pub fn read_struct<T: AsBytes + FromBytes>(fd: &mut std::fs::File) -> io::Result<T> {
    let mut ret: T = T::new_zeroed();
    fd.read_exact(ret.as_bytes_mut())?;

    Ok(ret)
}

pub fn parse_pe(filename: &Path) -> anyhow::Result<(std::fs::File, MZHeader, PEHeader, u32, u32)> {
    let mut fd = std::fs::File::open(filename)?;

    /* Check for an MZ header */
    let mz_header: MZHeader = read_struct(&mut fd)?;
    if &mz_header.signature != b"MZ" {
        anyhow::bail!("No MZ header present");
    }

    /* Seek to where the PE header should be */
    if fd.seek(SeekFrom::Start(mz_header.new_header as u64))? != mz_header.new_header as u64 {
        anyhow::bail!("Failed to seek to PE header");
    }

    /* Check for a PE header */
    let pe_header: PEHeader = read_struct(&mut fd)?;
    if &pe_header.signature != b"PE\0\0" {
        anyhow::bail!("No PE header present");
    }

    /* Grab the number of tables from the bitness-specific table */
    let (image_size, num_tables) = match pe_header.machine {
        IMAGE_FILE_MACHINE_I386 => {
            let opthdr: WindowsPEHeader32 = read_struct(&mut fd)?;
            (opthdr.size_of_image, opthdr.num_tables)
        }
        IMAGE_FILE_MACHINE_IA64 | IMAGE_FILE_MACHINE_AMD64 => {
            let opthdr: WindowsPEHeader64 = read_struct(&mut fd)?;
            (opthdr.size_of_image, opthdr.num_tables)
        }
        _ => anyhow::bail!("Unsupported PE machine type"),
    };

    Ok((fd, mz_header, pe_header, image_size, num_tables))
}
