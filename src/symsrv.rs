#![allow(unknown_lints)]
#![warn(clippy::all)]
#![allow(clippy::needless_return)]

use std::{path::PathBuf, str::FromStr};

extern crate futures;
extern crate indicatif;
extern crate reqwest;
extern crate tokio;

use anyhow::Context;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use thiserror::Error;

use futures::stream::StreamExt;
use tokio::io::AsyncWriteExt;

mod style {
    use indicatif::ProgressStyle;

    pub fn bar() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(
                "[{elapsed_precise}] {bar:.cyan/blue} {bytes:>12}/{total_bytes:12} {wide_msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  ")
    }

    pub fn spinner() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {spinner} {bytes_per_sec:>10} {wide_msg}")
            .unwrap()
    }
}

/// Information about a symbol file resource.
pub enum SymFileInfo {
    Exe(ExeInfo),
    Pdb(PdbInfo),
}

impl ToString for SymFileInfo {
    fn to_string(&self) -> String {
        // The middle component of the resource's path on a symbol.
        match self {
            SymFileInfo::Exe(i) => format!("{:08x}{:x}", i.timestamp, i.size),
            SymFileInfo::Pdb(i) => format!("{:032X}{:x}", i.guid, i.age),
        }
    }
}

/// Executable file information relevant to a symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeInfo {
    pub timestamp: u32,
    pub size: u32,
}

/// PDB file information relevant to a symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbInfo {
    pub guid: u128,
    pub age: u32,
}

#[derive(Error, Debug)]
enum DownloadError {
    /// Server returned a 404 error. Try the next one.
    #[error("Server returned 404 not found")]
    FileNotFound,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
enum DownloadStatus {
    /// The symbol file already exists in the filesystem.
    AlreadyExists,
    /// The symbol file was successfully downloaded from the remote server.
    DownloadedOk,
}

enum RemoteFileType {
    /// HTTP-accessible URL (with a response already received)
    Url(reqwest::Response),
    /// Path on a network share
    Path(String),
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

/// A symbol server, defined by the user with the syntax `SRV*<cache_path>*<server_url>`.
pub struct SymSrv {
    /// The base URL for a symbol server, e.g: `https://msdl.microsoft.com/download/symbols`
    pub server_url: String,
    /// The base path for the local symbol cache, e.g: `C:\Symcache`
    pub cache_path: String,
}

impl FromStr for SymSrv {
    type Err = anyhow::Error;

    fn from_str(srv: &str) -> Result<Self, Self::Err> {
        // Split the path out by asterisks.
        let directives: Vec<&str> = srv.split('*').collect();

        // Ensure that the path starts with `SRV*` - the only form we currently support.
        match directives.first() {
            // Simply exit the match statement if the directive is "SRV"
            Some(x) => {
                if "SRV" == *x {
                    if directives.len() != 3 {
                        anyhow::bail!("");
                    }

                    // Alright, the directive is of the proper form. Return the server and filepath.
                    return Ok(SymSrv {
                        server_url: directives[2].to_string(),
                        cache_path: directives[1].to_string(),
                    });
                }
            }

            None => {
                anyhow::bail!("Unsupported server string form");
            }
        };

        unreachable!();
    }
}

/// A list of symbol servers, defined by the user with a semicolon-separated list.
pub struct SymSrvList(pub Box<[SymSrv]>);

impl FromStr for SymSrvList {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let server_list: Vec<&str> = s.split(';').collect();
        if server_list.is_empty() {
            anyhow::bail!("Invalid server string");
        }

        let vec = server_list
            .into_iter()
            .map(|symstr| symstr.parse::<SymSrv>())
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(SymSrvList(vec.into_boxed_slice()))
    }
}

/// Attempt to download a single resource from a single symbol server.
async fn download_single(
    client: &reqwest::Client,
    srv: &SymSrv,
    mp: Option<&MultiProgress>,
    name: &str,
    hash: &str,
) -> Result<DownloadStatus, DownloadError> {
    // e.g: "ntkrnlmp.pdb/32C1A669D5FFEFD41091F636CFDB6E991"
    let file_rel_folder = format!("{}/{}", name, hash);

    // The name of the file on the local filesystem
    let file_name = format!("{}/{}/{}", srv.cache_path, file_rel_folder, name);
    // The path to the file's folder on the remote server
    let file_folder_url = format!("{}/{}", srv.server_url, file_rel_folder);

    // Attempt to remove any existing temporary files first.
    // Silently ignore failures since we don't care if this fails.
    let file_name_tmp = format!("{}.tmp", file_name);
    let _ = tokio::fs::remove_file(&file_name_tmp).await;

    // Check to see if the file already exists. If so, skip it.
    if std::path::Path::new(&file_name).exists() {
        return Ok(DownloadStatus::AlreadyExists);
    }

    // Attempt to retrieve the file.
    let remote_file = {
        let pdb_req = client
            .get::<&str>(&format!("{}/{}", file_folder_url, name))
            .send()
            .await
            .context("failed to request remote file")?;
        if pdb_req.status().is_success() {
            RemoteFileType::Url(pdb_req)
        } else {
            // Try a `file.ptr` redirection URL
            let fileptr_req = client
                .get::<&str>(&format!("{}/file.ptr", file_folder_url))
                .send()
                .await
                .context("failed to request file.ptr")?;
            if !fileptr_req.status().is_success() {
                // Attempt another server instead
                Err(DownloadError::FileNotFound)?;
            }

            let url = fileptr_req
                .text()
                .await
                .context("failed to get file.ptr contents")?;

            // FIXME: Would prefer not to unwrap the iterator results...
            let mut url_iter = url.split(":");
            let url_type = url_iter.next().unwrap();
            let url = url_iter.next().unwrap();

            match url_type {
                "PATH" => RemoteFileType::Path(url.to_string()),

                // Try another server.
                "MSG" => return Err(DownloadError::FileNotFound),

                typ => {
                    unimplemented!(
                        "Unknown symbol redirection pointer type {typ}!\n{url_type}:{url}"
                    );
                }
            }
        }
    };

    // Create the directory tree.
    tokio::fs::create_dir_all(format!("{}/{}", srv.cache_path, file_rel_folder))
        .await
        .context("failed to create symbol directory tree")?;

    match remote_file {
        RemoteFileType::Url(mut res) => {
            // N.B: If the server sends us a content-length header, use it to display a progress bar.
            // Otherwise, just display a spinner progress bar.
            let dl_pb = if let Some(m) = mp {
                match res.content_length() {
                    Some(len) => {
                        let dl_pb = m.add(ProgressBar::new(len));
                        dl_pb.set_style(style::bar());

                        Some(dl_pb)
                    }

                    None => {
                        let dl_pb = m.add(ProgressBar::new_spinner());
                        dl_pb.set_style(style::spinner());
                        dl_pb.enable_steady_tick(std::time::Duration::from_millis(5));

                        Some(dl_pb)
                    }
                }
            } else {
                None
            };

            if let Some(dl_pb) = &dl_pb {
                dl_pb.set_message(format!("{}/{}", hash, name));
            }

            // Create the output file.
            let mut file = tokio::fs::File::create(&file_name_tmp)
                .await
                .context("failed to create output pdb")?;

            // N.B: We use this in lieu of tokio::io::copy so we can update the download progress.
            while let Some(chunk) = res.chunk().await.context("failed to download pdb chunk")? {
                if let Some(dl_pb) = &dl_pb {
                    dl_pb.inc(chunk.len() as u64);
                }

                file.write(&chunk)
                    .await
                    .context("failed to write pdb chunk")?;
            }

            // Rename the temporary copy to the final name
            tokio::fs::rename(&file_name_tmp, file_name)
                .await
                .context("failed to rename pdb")?;

            Ok(DownloadStatus::DownloadedOk)
        }

        RemoteFileType::Path(path) => {
            // Attempt to open the file via the filesystem.
            let mut remote_file = tokio::fs::File::open(path)
                .await
                .context("failed to open remote file")?;
            let metadata = remote_file
                .metadata()
                .await
                .context("failed to fetch remote metadata")?;

            let dl_pb = if let Some(m) = mp {
                let dl_pb = m.add(ProgressBar::new(metadata.len()));
                dl_pb.set_style(style::bar());

                dl_pb.set_message(format!("{}/{}", hash, name));

                Some(dl_pb)
            } else {
                None
            };

            // Create the output file.
            let mut file = tokio::fs::File::create(&file_name_tmp)
                .await
                .context("failed to create output pdb")?;

            if let Some(dl_pb) = dl_pb {
                tokio::io::copy(&mut dl_pb.wrap_async_read(remote_file), &mut file)
                    .await
                    .context("failed to copy pdb")?;
            } else {
                tokio::io::copy(&mut remote_file, &mut file)
                    .await
                    .context("failed to copy pdb")?;
            }

            // Rename the temporary copy to the final name
            tokio::fs::rename(&file_name_tmp, file_name)
                .await
                .context("failed to rename pdb")?;

            Ok(DownloadStatus::DownloadedOk)
        }
    }
}

/// Connect to Azure and authenticate requests using a PAT.
///
/// Reference: https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows
fn connect_pat(token: &str) -> anyhow::Result<reqwest::Client> {
    use reqwest::header;

    let b64 = base64::encode(token);

    let mut headers = header::HeaderMap::new();
    let auth_value = header::HeaderValue::from_str(&format!("Basic {b64}"))?;
    headers.insert(header::AUTHORIZATION, auth_value);

    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

fn connect_server(srv: &SymSrv) -> anyhow::Result<reqwest::Client> {
    // Determine if the URL is a known URL that requires OAuth2 authorization.
    use url::{Host, Url};

    let url = Url::parse(&srv.server_url)?;
    match url.host() {
        Some(Host::Domain(d)) => {
            match d {
                // Azure DevOps
                // TODO: Ugh, fixme. Need to match domain name only.
                "microsoft.artifacts.visualstudio.com" => {
                    let pat = std::env::var("AZ_PAT").context("var AZ_PAT is not defined!")?;
                    if url.scheme() != "https" {
                        anyhow::bail!("This URL must be over https!");
                    }

                    Ok(connect_pat(&pat)?)
                }

                _ => {
                    // Unknown URL; return a fresh client.
                    Ok(reqwest::Client::new())
                }
            }
        }
        Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => {
            // Just return a new client.
            Ok(reqwest::Client::new())
        }
    }
}

/// Download and cache a single file in the symbol store described by `srvstr`,
/// and then return its path.
pub async fn download_file(
    srvstr: String,
    name: &str,
    info: &SymFileInfo,
) -> anyhow::Result<PathBuf> {
    todo!()
}

pub async fn download_manifest(srvstr: String, files: Vec<String>) -> anyhow::Result<()> {
    // First, parse the server string to figure out where we're supposed to fetch symbols from,
    // and where to.
    let srvs = SymSrvList::from_str(&srvstr)?;

    // Couple the servers with a reqwest client.
    let srvs = srvs
        .0
        .into_iter()
        .map(|s| (s.clone(), connect_server(s).unwrap()))
        .collect::<Box<[_]>>();

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
            let srvs = &srvs;
            let pb = pb.clone();
            let m = &m;

            async move {
                pb.inc(1);

                for (srv, client) in srvs.iter() {
                    let e = ManifestEntry::from_str(&line).unwrap();

                    match download_single(client, srv, Some(m), &e.name, &e.hash).await {
                        Ok(r) => return Ok(r),
                        Err(e) => match e {
                            // Try next server.
                            DownloadError::FileNotFound => continue,
                            e => return Err(e),
                        },
                    }
                }

                Err(DownloadError::FileNotFound)
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
