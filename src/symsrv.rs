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
    /// A raw symsrv-compatible hash.
    RawHash(String),
}

impl ToString for SymFileInfo {
    fn to_string(&self) -> String {
        // The middle component of the resource's path on a symbol.
        match self {
            SymFileInfo::Exe(i) => i.to_string(),
            SymFileInfo::Pdb(i) => i.to_string(),
            SymFileInfo::RawHash(h) => h.clone(),
        }
    }
}

/// Executable file information relevant to a symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeInfo {
    pub timestamp: u32,
    pub size: u32,
}

impl ToString for ExeInfo {
    fn to_string(&self) -> String {
        format!("{:08x}{:x}", self.timestamp, self.size)
    }
}

/// PDB file information relevant to a symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbInfo {
    pub guid: u128,
    pub age: u32,
}

impl ToString for PdbInfo {
    fn to_string(&self) -> String {
        format!("{:032X}{:x}", self.guid, self.age)
    }
}

#[derive(Error, Debug)]
pub enum DownloadError {
    /// Server returned a 404 error. Try the next one.
    #[error("Server returned 404 not found")]
    FileNotFound,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
pub enum DownloadStatus {
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

/// A symbol server, defined by the user with the syntax `SRV*<cache_path>*<server_url>`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
) -> Result<(DownloadStatus, PathBuf), DownloadError> {
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
        return Ok((DownloadStatus::AlreadyExists, file_name.into()));
    }

    // Attempt to retrieve the file.
    let remote_file = {
        let pdb_req = client
            .get::<&str>(&format!("{}/{}", file_folder_url, name))
            .send()
            .await
            .context("failed to request remote file")?;
        if pdb_req.status().is_success() {
            if let Some(mime) = pdb_req.headers().get(reqwest::header::CONTENT_TYPE) {
                let mime = mime
                    .to_str()
                    .expect("Content-Type header not a valid string")
                    .parse::<mime::Mime>()
                    .expect("Content-Type header not a valid MIME type");

                if mime.subtype() == mime::HTML {
                    // Azure DevOps will do this if the authentication header isn't correct...
                    panic!(
                        "Server {} returned an invalid Content-Type of {mime}",
                        srv.server_url
                    );
                }
            }

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
                "MSG" => return Err(DownloadError::FileNotFound), // Try another server.
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
            // TODO: Should have the library user provide a trait that allows us to create a progress bar
            // in abstract
            let dl_pb = if let Some(m) = mp {
                let dl_pb = match res.content_length() {
                    Some(len) => {
                        let dl_pb = m.add(ProgressBar::new(len));
                        dl_pb.set_style(style::bar());

                        dl_pb
                    }

                    None => {
                        let dl_pb = m.add(ProgressBar::new_spinner());
                        dl_pb.set_style(style::spinner());
                        dl_pb.enable_steady_tick(std::time::Duration::from_millis(5));

                        dl_pb
                    }
                };

                dl_pb.set_message(format!("{}/{}", hash, name));
                Some(dl_pb)
            } else {
                None
            };

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
            tokio::fs::rename(&file_name_tmp, &file_name)
                .await
                .context("failed to rename pdb")?;

            Ok((DownloadStatus::DownloadedOk, file_name.into()))
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
            tokio::fs::rename(&file_name_tmp, &file_name)
                .await
                .context("failed to rename pdb")?;

            Ok((DownloadStatus::DownloadedOk, file_name.into()))
        }
    }
}

/// Connect to Azure and authenticate requests using a PAT.
///
/// Reference: https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows
fn connect_pat(token: &str) -> anyhow::Result<reqwest::Client> {
    use reqwest::header;

    // N.B: According to ADO documentation, the token needs to be preceded by an arbitrary
    // string followed by a colon. The arbitrary string can be empty.
    let b64 = base64::encode(format!(":{token}"));

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
                d if d.ends_with("artifacts.visualstudio.com") => {
                    let pat = std::env::var("ADO_PAT").context("var ADO_PAT is not defined!")?;
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

pub struct SymContext {
    /// The list of connected servers.
    servers: Box<[(SymSrv, reqwest::Client)]>,
}

impl SymContext {
    pub fn new(srvstr: String) -> anyhow::Result<Self> {
        // First, parse the server string to figure out where we're supposed to fetch symbols from,
        // and where to.
        let servers = SymSrvList::from_str(&srvstr)?;

        // Couple the servers with a reqwest client.
        let servers = servers
            .0
            .into_iter()
            .map(|s| (s.clone(), connect_server(s).unwrap()))
            .collect::<Box<[_]>>();

        Ok(Self { servers })
    }

    /// Attempt to find a single file in the symbol store associated with this context.
    ///
    /// If the file is found, its cache path will be returned.
    pub fn find_file(&self, name: &str, info: &SymFileInfo) -> Option<PathBuf> {
        for (srv, _) in self.servers.iter() {
            let hash = info.to_string();

            // The file should be in each cache directory under the following path:
            // "<cache_dir>/<name>/<hash>/<name>"
            let path = PathBuf::from(&srv.cache_path)
                .join(name)
                .join(hash)
                .join(name);

            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    /// Download and cache a single file in the symbol store associated with this context,
    /// and then return its path on the local system.
    pub async fn download_file(
        &self,
        name: &str,
        info: &SymFileInfo,
    ) -> Result<PathBuf, DownloadError> {
        for (srv, client) in self.servers.iter() {
            let hash = info.to_string();

            match download_single(client, srv, None, name, &hash).await {
                Ok((status, path)) => return Ok(path),
                Err(e) => match e {
                    // Try another server.
                    DownloadError::FileNotFound => continue,
                    e => return Err(e),
                },
            }
        }

        Err(DownloadError::FileNotFound)
    }

    /// Download (displaying progress) and cache a single file in the symbol store associated with this context,
    /// and then return its path on the local system.
    pub async fn download_file_progress(
        &self,
        name: &str,
        info: &SymFileInfo,
        mp: &MultiProgress,
    ) -> Result<PathBuf, DownloadError> {
        for (srv, client) in self.servers.iter() {
            let hash = info.to_string();

            match download_single(client, srv, Some(mp), name, &hash).await {
                Ok((status, path)) => return Ok(path),
                Err(e) => match e {
                    // Try another server.
                    DownloadError::FileNotFound => continue,
                    e => return Err(e),
                },
            }
        }

        Err(DownloadError::FileNotFound)
    }
}
