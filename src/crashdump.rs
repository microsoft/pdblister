use core::str;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Context;
use minidump::{CodeView, MinidumpModuleList};

pub(crate) fn get_module_list_from_crash(
    crash: &Path,
    binaries: bool,
) -> anyhow::Result<Vec<String>> {
    // Map the crashdump
    let dump = minidump::Minidump::read_path(crash).context("failed to parse crashdump")?;

    let mut manifest = Vec::new();

    for module in dump
        .get_stream::<MinidumpModuleList>()
        .context("failed to get module list from crashdump")?
        .iter()
    {
        if binaries {
            match PathBuf::from_str(&module.name) {
                Ok(bin_path) => match bin_path.file_name().and_then(|x| x.to_str()) {
                    Some(bin_filename) => {
                        manifest.push(format!(
                            "{},{:x}{:x},2",
                            bin_filename, module.raw.time_date_stamp, module.raw.size_of_image
                        ));
                    }
                    None => println!("Module '{}' binary is missing path stem", module.name),
                },
                Err(_) => println!("Module '{}' is an invalid path", module.name),
            }
        }

        match &module.codeview_info {
            Some(CodeView::Pdb70(info)) => {
                // Get the pdb name
                // Sometimes this includes a path, so we clean that off
                // Sometimes this glob of data also includes non-null stuff after a null (e.g. '000000000000000'), so we strip that too
                let pdb_path_slice =
                    if let Some(null_offset) = info.pdb_file_name.iter().position(|x| *x == 0) {
                        &info.pdb_file_name[0..null_offset]
                    } else {
                        &info.pdb_file_name
                    };

                if let Ok(mut pdb) = str::from_utf8(pdb_path_slice) {
                    // Extract the file name from the pdb name, if it exists
                    if let Some(stem) = Path::new(pdb).file_name().and_then(OsStr::to_str) {
                        pdb = stem;
                    }

                    manifest.push(format!(
                    "{},{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:x},1",
                    pdb,
                    info.signature.data1,
                    info.signature.data2,
                    info.signature.data3,
                    info.signature.data4[0],
                    info.signature.data4[1],
                    info.signature.data4[2],
                    info.signature.data4[3],
                    info.signature.data4[4],
                    info.signature.data4[5],
                    info.signature.data4[6],
                    info.signature.data4[7],
                    info.age
                ));
                } else {
                    println!(
                        "Module '{}' has invalid pdb path in codeview information",
                        module.name
                    )
                }
            }
            Some(CodeView::Pdb20(_)) => {
                println!(
                    "Module '{}' has old and unhandled PDB codeview information",
                    module.name
                )
            }
            Some(CodeView::Elf(_)) => {
                println!("Module '{}' has ELF codeview information (?!)", module.name)
            }
            Some(CodeView::Unknown(_)) => {
                println!("Module '{}' has unknown codeview information", module.name)
            }
            None => println!(
                "Module '{}' does not contain codeview information",
                module.name
            ),
        }
    }

    Ok(manifest)
}
