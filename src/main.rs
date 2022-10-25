#![forbid(unsafe_code)]

//! This is a tiny project to be a quick alternative to symchk for generating
//! manifests. This mimics symchk of the form `symchk /om manifest /r <path>`
//! but only looks for MZ/PE files.
//!
//! Due to symchk doing some weird things it can often crash or get stuck in
//! infinite loops. Thus this is a stricter (and much faster) alternative.
//!
//! The output manifest is compatible with symchk and thus symchk is currently
//! used for the actual download. To download symbols after this manifest
//! has been generated use `symchk /im manifest /s <symbol path>`
use anyhow::Context;
use indicatif::{MultiProgress, ProgressStyle};

use std::env;
use std::io::SeekFrom;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;

use futures::{stream, Stream, StreamExt};
use indicatif::ProgressBar;
use tokio::{
    fs::{self, DirEntry},
    io::AsyncWriteExt,
};

use crate::symsrv::{DownloadError, DownloadStatus, SymContext, SymFileInfo};

mod pe;
mod symsrv;

const USAGE: &'static str = "Usage:

    pdblister [manifest | download | filestore | clean] <filepath>
 
    === Create manifest === 
    
        pdblister manifest <filepath>

        This command takes in a filepath to recursively search for files that
        have a corresponding PDB. This creates a file called `manifest` which
        is compatible with symchk.
        
        For example `pdblister manifest C:\\windows` will create `manifest`
        containing all of the PDB signatures for all of the files in
        C:\\windows.

    === Download from manifest ===

        pdblister download <sympath>

        This command takes no parameters. It simply downloads all the PDBs
        specified in the `manifest` file.

    === Download single executable ===

        pdblister download_single <sympath> <exepath>

        This command will take a symbol server URL and executable path, and
        use the symbol server to download the PDB file for the executable to
        the cache directory.

    === Create a file store ===

        pdblister filestore <filepath>

        This command recursively walks filepath to find all PEs. Any PE file
        that is found is copied to the local directory 'filestore' using the
        layout that symchk.exe uses to store normal files. This is used to
        create a store of all PEs (such as .dlls), which can be used by a
        kernel debugger to read otherwise paged out memory by downloading the
        original PE source file from this filestore.

        To use this filestore simply merge the contents in with a symbol
        store/cache path. We keep it separate in this tool just to make it
        easier to only get PDBs if that's all you really want.

    === Clean ===

        pdblister clean

        This command removes the `manifest` file as well as the symbol folder
        and the filestore folder
";

/// Given a `path`, return a stream of all the files recursively found from
/// that path.
fn recursive_listdir(
    path: impl Into<PathBuf>,
) -> impl Stream<Item = io::Result<DirEntry>> + Send + 'static {
    async fn one_level(path: PathBuf, to_visit: &mut Vec<PathBuf>) -> io::Result<Vec<DirEntry>> {
        let mut dir = fs::read_dir(path).await?;
        let mut files = Vec::new();

        while let Some(child) = dir.next_entry().await? {
            if child.metadata().await?.is_dir() {
                to_visit.push(child.path());
            } else {
                files.push(child)
            }
        }

        Ok(files)
    }

    stream::unfold(vec![path.into()], |mut to_visit| async {
        let path = to_visit.pop()?;
        let file_stream = match one_level(path, &mut to_visit).await {
            Ok(files) => stream::iter(files).map(Ok).left_stream(),
            Err(e) => stream::once(async { Err(e) }).right_stream(),
        };

        Some((file_stream, to_visit))
    })
    .flatten()
}

fn get_file_path(filename: &Path) -> anyhow::Result<String> {
    let (_, _, pe_header, image_size, _) = pe::parse_pe(filename)?;

    let filename = filename
        .file_name()
        .context("Failed to get file name")?
        .to_str()
        .context("Failed to convert file name")?;

    let filestr = format!(
        "filestore/{}/{:08x}{:x}/{}",
        filename,
        { pe_header.timestamp },
        image_size,
        filename
    );

    /* For hashes
    let filestr = format!("{},{:08x}{:x},1",
                          filename.file_name()
                            .unwrap().to_str().unwrap(),
                          pe_header.timestamp,
                          image_size);*/

    Ok(filestr)
}

/// Given a `filename`, attempt to parse out any mention of a PDB file in it.
///
/// This returns success if it successfully parses the MZ, PE, finds a debug
/// header, matches RSDS signature, and contains a valid reference to a PDB.
///
/// Returns a string which is the same representation you get from `symchk`
/// when outputting a manifest for the PDB "<filename>,<guid><age>,1"
fn get_pdb(filename: &Path) -> anyhow::Result<String> {
    let (mut fd, mz_header, pe_header, _, num_tables) = pe::parse_pe(filename)?;

    /* Load all the data directories into a vector */
    let mut data_dirs = Vec::new();
    for _ in 0..num_tables {
        let datadir: pe::ImageDataDirectory = pe::read_struct(&mut fd)?;
        data_dirs.push(datadir);
    }

    /* Debug directory is at offset 6, validate we have at least 7 entries */
    if data_dirs.len() < 7 {
        anyhow::bail!("No debug data directory");
    }

    /* Grab the debug table */
    let debug_table = data_dirs[6];
    if debug_table.vaddr == 0 || debug_table.size == 0 {
        anyhow::bail!("Debug directory not present or zero sized");
    }

    /* Validate debug table size is sane */
    let iddlen = std::mem::size_of::<pe::ImageDebugDirectory>() as u32;
    let debug_table_ents = debug_table.size / iddlen;
    if (debug_table.size % iddlen) != 0 || debug_table_ents == 0 {
        anyhow::bail!("No debug entries or not mod ImageDebugDirectory");
    }

    /* Seek to where the section table should be */
    let section_headers =
        mz_header.new_header as u64 + 0x18 + pe_header.optional_header_size as u64;
    if fd.seek(SeekFrom::Start(section_headers))? != section_headers {
        anyhow::bail!("Failed to seek to section table");
    }

    /* Parse all the sections into a vector */
    let mut sections = Vec::new();
    for _ in 0..pe_header.num_sections {
        let sechdr: pe::ImageSectionHeader = pe::read_struct(&mut fd)?;
        sections.push(sechdr);
    }

    let debug_raw_ptr = {
        /* Find the section the debug table belongs to */
        let mut debug_data = None;
        for section in &sections {
            /* We use raw_data_size instead of vsize as we are not loading the
             * file and only care about raw contents in the file.
             */
            let secrange = section.vaddr..section.vaddr + section.raw_data_size;

            /* Check if the entire debug table is contained in this sections
             * virtual address range.
             */
            if secrange.contains(&{ debug_table.vaddr })
                && secrange.contains(&(debug_table.vaddr + debug_table.size - 1))
            {
                debug_data = Some(debug_table.vaddr - section.vaddr + section.pointer_to_raw_data);
                break;
            }
        }

        match debug_data {
            Some(d) => d as u64,
            None => anyhow::bail!("Unable to find debug data"),
        }
    };

    /* Seek to where the debug directories should be */
    if fd.seek(SeekFrom::Start(debug_raw_ptr))? != debug_raw_ptr {
        anyhow::bail!("Failed to seek to debug directories");
    }

    /* Look through all debug table entries for codeview entries */
    for _ in 0..debug_table_ents {
        let de: pe::ImageDebugDirectory = pe::read_struct(&mut fd)?;

        if de.typ == pe::IMAGE_DEBUG_TYPE_CODEVIEW {
            /* Seek to where the codeview entry should be */
            let cvo = de.pointer_to_raw_data as u64;
            if fd.seek(SeekFrom::Start(cvo))? != cvo {
                anyhow::bail!("Failed to seek to codeview entry");
            }

            let cv: pe::CodeviewEntry = pe::read_struct(&mut fd)?;
            if &cv.signature != b"RSDS" {
                anyhow::bail!("No RSDS signature present in codeview ent");
            }

            /* Calculate theoretical string length based on the size of the
             * section vs the size of the header */
            let cv_strlen = de.size_of_data as usize - std::mem::size_of_val(&cv);

            /* Read in the debug path */
            let mut dpath = vec![0u8; cv_strlen];
            fd.read_exact(&mut dpath)?;

            /* PDB strings are utf8 and null terminated, find the first null
             * and we will split it there.
             */
            if let Some(null_strlen) = dpath.iter().position(|&x| x == 0) {
                let dpath = std::str::from_utf8(&dpath[..null_strlen])?;

                /* Further, since this path can be a full path, we get only
                 * the filename component of this path.
                 */
                if let Some(pdbfilename) = Path::new(dpath).file_name() {
                    /* This is the format string used by symchk.
                     * Original is in SymChkCheckFiles()
                     * "%s,%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x,1"
                     */
                    let guidstr = format!("{},{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:x},1",
                                          pdbfilename.to_str().context("Failed to get PDB filename")?,
                                          {cv.guid_a}, {cv.guid_b}, {cv.guid_c},
                                          {cv.guid_d[0]}, {cv.guid_d[1]},
                                          {cv.guid_d[2]}, {cv.guid_d[3]},
                                          {cv.guid_d[4]}, {cv.guid_d[5]},
                                          {cv.guid_d[6]}, {cv.guid_d[7]},
                                          {cv.age});
                    return Ok(guidstr);
                } else {
                    anyhow::bail!("Could not parse file from RSDS path");
                }
            } else {
                anyhow::bail!("Failed to find null terminiator in RSDS");
            }
        }
    }

    anyhow::bail!("Failed to find RSDS codeview directory")
}

#[derive(Debug, Clone)]
struct ManifestEntry {
    /// The PDB's name
    name: String,
    /// The hash plus age of the PDB
    hash: String,
    /// The version number (maybe?)
    version: u32,
}

impl FromStr for ManifestEntry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let elements = s.split(",").collect::<Vec<_>>();
        if elements.len() != 3 {
            anyhow::bail!("Invalid manifest line: \"{s}\"");
        }

        Ok(Self {
            name: elements[0].to_string(),
            hash: elements[1].to_string(),
            version: u32::from_str(elements[2])?,
        })
    }
}

pub async fn download_manifest(srvstr: String, files: Vec<String>) -> anyhow::Result<()> {
    let ctx = SymContext::new(srvstr).context("failed to create symbol context")?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let m = MultiProgress::new();

    // Create a progress bar.
    let pb = m.add(ProgressBar::new(files.len() as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>10}/{len:10} ({eta}) {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    // Set up our asynchronous code block.
    // This block will be lazily executed when something awaits on it, such as the tokio thread pool below.
    let queries = futures::stream::iter(
        // Map the files vector using a closure, such that it's converted from a Vec<String>
        // into a Vec<Result<T, E>>
        files.into_iter().map(|line| {
            // Take explicit references to a few variables and move them into the async block.
            let ctx = &ctx;
            let pb = pb.clone();
            let m = &m;

            async move {
                pb.inc(1);

                let e = ManifestEntry::from_str(&line).unwrap();
                let info = SymFileInfo::RawHash(e.hash);

                if ctx.find_file(&e.name, &info).is_some() {
                    return Ok(DownloadStatus::AlreadyExists);
                }

                match ctx.download_file_progress(&e.name, &info, m).await {
                    Ok(_) => Ok(DownloadStatus::DownloadedOk),
                    Err(e) => Err(e),
                }
            }
        }),
    )
    .buffer_unordered(32)
    .collect::<Vec<Result<DownloadStatus, DownloadError>>>();

    // N.B: The buffer_unordered bit above allows us to feed in 64 requests at a time to tokio.
    // That way we don't exhaust system resources in the networking stack or filesystem.
    let output = queries.await;

    pb.finish();

    let mut ok = 0u64;
    let mut ok_exists = 0u64;
    let mut err = 0u64;

    // Collect output results.
    output.iter().for_each(|x| match x {
        Err(_) => {
            err += 1;
        }

        Ok(s) => match s {
            DownloadStatus::AlreadyExists => ok_exists += 1,
            DownloadStatus::DownloadedOk => ok += 1,
        },
    });

    println!("{} files failed to download", err);
    println!("{} files already downloaded", ok_exists);
    println!("{} files downloaded successfully", ok);

    return Ok(());
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let it = Instant::now();

    if args.len() == 3 && args[1] == "manifest" {
        /* List all files in the directory specified by args[2] */
        let dir = Path::new(args[2].as_str());
        let listing: Vec<Result<DirEntry, io::Error>> = recursive_listdir(dir).collect().await;

        let pb = ProgressBar::new(listing.len() as u64);

        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>7}/{len:7} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("##-"),
        );

        // Map the listing into strings to write into the manifest
        let tasks: Vec<_> = listing
            .into_iter()
            .filter_map(move |e| {
                let pb = pb.clone();

                match e {
                    Ok(e) => Some(tokio::spawn(async move {
                        pb.inc(1);

                        match get_pdb(&e.path()) {
                            Ok(manifest_str) => Some(manifest_str),
                            Err(_) => None,
                        }
                    })),

                    Err(_) => None,
                }
            })
            .collect();

        let mut output_file = tokio::fs::File::create("manifest")
            .await
            .context("Failed to create output manifest file")?;

        for task in tasks {
            if let Some(e) = task.await.unwrap() {
                output_file
                    .write(&format!("{}\n", &e).as_bytes())
                    .await
                    .context("Failed to write to output manifest file")?;
            }
        }
    } else if args.len() == 3 && args[1] == "download" {
        /* Read the entire manifest file into a string */
        let mut buf = String::new();
        let mut fd = std::fs::File::open("manifest").context("Failed to open PDB manifest file")?;
        fd.read_to_string(&mut buf).expect("Failed to read file");

        /* Split the file into lines and collect into a vector */
        let mut lines: Vec<String> = buf.lines().map(|l| String::from(l)).collect();

        /* If there is nothing to download, return out early */
        if lines.len() == 0 {
            print!("Nothing to download\n");
            return Ok(());
        }

        print!("Original manifest has {} PDBs\n", lines.len());

        lines.sort();
        lines.dedup();

        print!("Deduped manifest has {} PDBs\n", lines.len());

        match download_manifest(args[2].clone(), lines).await {
            Ok(_) => println!("Success!"),
            Err(e) => println!("Failed: {:#}", e),
        }
    } else if args.len() == 4 && args[1] == "download_single" {
        let ctx = SymContext::new(args[2].clone()).context("failed to create symbol context")?;

        // Resolve the PDB for the executable specified.
        let e = ManifestEntry::from_str(
            &get_pdb(Path::new(&args[3])).context("failed to resolve PDB hash")?,
        )
        .unwrap();
        let info = SymFileInfo::RawHash(e.hash);

        if let Some(p) = ctx.find_file(&e.name, &info) {
            println!("file already cached: {}", p.to_string_lossy());
        } else {
            match ctx.download_file(&e.name, &info).await {
                Ok(p) => println!("file successfully downloaded: {}", p.to_string_lossy()),
                Err(e) => Err(e).context("failed to download PDB")?,
            };
        }
    } else if args.len() == 3 && args[1] == "filestore" {
        /* List all files in the directory specified by args[2] */
        let dir = Path::new(args[2].as_str());
        let listing = recursive_listdir(&dir);

        listing
            .for_each(|entry| async {
                if let Ok(e) = entry {
                    if let Ok(fsname) = get_file_path(&e.path()) {
                        let fsname = Path::new(&fsname);

                        if !fsname.exists() {
                            let dir = fsname.parent().unwrap();
                            tokio::fs::create_dir_all(dir)
                                .await
                                .expect("Failed to create filestore directory");

                            if let Err(_) = tokio::fs::copy(&e.path(), fsname).await {
                                print!("Failed to copy file {:?}\n", &e.path());
                            }
                        }
                    }
                }
            })
            .await;
    } else if args.len() == 2 && args[1] == "clean" {
        /* Ignores all errors during clean */
        let _ = std::fs::remove_dir_all("symbols");
        let _ = std::fs::remove_dir_all("filestore");
        let _ = std::fs::remove_file("manifest");
    } else {
        /* Print out usage information */
        print!("{}", USAGE);
    }

    print!("Time elapsed: {:.3} seconds\n", it.elapsed().as_secs_f64());
    Ok(())
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}
