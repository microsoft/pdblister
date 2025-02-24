use std::{
    convert::TryInto,
    ffi::OsStr,
    io::{ErrorKind, Read, Seek},
    ops::Range,
    path::Path,
};

use anyhow::Context;
use kdmp_parser::{Gva, Gxa};

use crate::{get_pdb_from_reader, pe};

struct DumpPE<'a> {
    dump: &'a kdmp_parser::KernelDumpParser,
    pe_range: &'a Range<Gva>,
    offset: isize,
}

impl<'a> Read for &mut DumpPE<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Trim the read to the end of the buffer in case it exceeds the PE in memory
        let pe_len: isize = (self.pe_range.end.u64() - self.pe_range.start.u64())
            .try_into()
            .unwrap();
        let read_size: usize = std::cmp::min(buf.len(), (pe_len - self.offset).try_into().unwrap());

        // Calculate the Gva to perform the read at
        let read_addr = Gva::new(self.pe_range.start.u64() + self.offset as u64);

        // Do the read
        match self.dump.virt_read(read_addr, &mut buf[0..read_size]) {
            Ok(read_bytes) => {
                let read_bytes_signed: isize = read_bytes.try_into().unwrap();
                self.offset += read_bytes_signed;
                Ok(read_bytes)
            }
            Err(err) => Err(std::io::Error::new(ErrorKind::Other, err)),
        }
    }
}

impl<'a> Seek for &mut DumpPE<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_offset: isize = match pos {
            std::io::SeekFrom::Current(x) => {
                let cur: i64 = self.offset.try_into().unwrap();
                (cur + x).try_into().unwrap()
            }
            std::io::SeekFrom::End(x) => {
                let end: i64 = self.pe_range.end.u64().try_into().unwrap();
                (end + x).try_into().unwrap()
            }
            std::io::SeekFrom::Start(x) => x.try_into().unwrap(),
        };

        self.offset = new_offset.try_into().unwrap();

        Ok(self.offset.try_into().unwrap())
    }
}

pub(crate) fn get_module_list_from_kernel_crash(
    crash: &Path,
    binaries: bool,
    include_user: bool,
) -> anyhow::Result<Vec<String>> {
    // Map the crashdump
    let reader =
        kdmp_parser::MappedFileReader::new(crash).context("failed to map kernel crashdump")?;
    let dump = kdmp_parser::KernelDumpParser::with_reader(reader)
        .context("failed to parse kernel crashdump")?;

    let mut manifest = Vec::new();

    let module_iter = dump.kernel_modules().chain(
        // If we're including user modules, chain it in
        if include_user {
            Some(dump.user_modules())
        } else {
            None
        }
        .into_iter()
        .flatten(),
    );

    for (module_range, module) in module_iter {
        let mut module_reader = DumpPE {
            dump: &dump,
            offset: 0,
            pe_range: module_range,
        };

        // If we're getting binaries too, record that now
        if binaries {
            // Get the base file name of the module
            let mut bin_name = module;
            if let Some(stem) = Path::new(module).file_name().and_then(OsStr::to_str) {
                bin_name = stem;
            }

            match pe::parse_pe(&mut module_reader) {
                Ok((_, _, pe_header, image_size, _)) => {
                    let timestamp = pe_header.timestamp;
                    manifest.push(format!("{},{:x}{:x},2", bin_name, timestamp, image_size));
                }
                Err(err) => {
                    eprintln!("Failed to get PE  for module '{}': {}", module, err)
                }
            }

            (&mut module_reader).seek(std::io::SeekFrom::Start(0))?;
        }

        match get_pdb_from_reader(&mut module_reader) {
            Ok(manifest_entry) => manifest.push(manifest_entry),
            Err(err) => eprintln!("Failed to get PDB for module '{}': {}", module, err),
        }
    }

    Ok(manifest)
}
