// #![allow(unknown_lints)]
// #![warn(clippy::all)]
// #![allow(clippy::needless_return)]

use std::path::PathBuf;

extern crate futures;
extern crate indicatif;
extern crate reqwest;
extern crate tokio;

use crate::{DownloadError, DownloadStatus, SymFileInfo, SymSrvSpec};

use anyhow::Context;
use indicatif::{MultiProgress, ProgressBar};

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

enum RemoteFileType {
    /// HTTP-accessible URL (with a response already received)
    Url(reqwest::Response),
    /// Path on a network share
    Path(String),
}

/// Attempt to download a single resource from a single symbol server.
async fn download_single(
    client: &reqwest::Client,
    srv: &SymSrvSpec,
    mp: Option<&MultiProgress>,
    name: &str,
    hash: &str,
) -> Result<(DownloadStatus, PathBuf), DownloadError> {
    // e.g: "ntkrnlmp.pdb/32C1A669D5FFEFD41091F636CFDB6E991"
    let file_rel_folder = format!("{}/{}", name, hash);

    // The name of the file on the local filesystem
    let file_name = srv.cache_path.join(&file_rel_folder).join(name);
    // The path to the file's folder on the remote server
    let file_folder_url = format!("{}/{}", srv.server_url, file_rel_folder);

    // Attempt to remove any existing temporary files first.
    // Silently ignore failures since we don't care if this fails.
    let file_name_tmp = file_name.with_extension("pdb.tmp");
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
            .await?;
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
                .await?;
            if !fileptr_req.status().is_success() {
                // Attempt another server instead
                Err(DownloadError::FileNotFound)?;
            }

            let url = fileptr_req
                .text()
                .await
                .context("failed to get file.ptr contents")?;

            // FIXME: Would prefer not to unwrap the iterator results...
            let mut url_iter = url.split(':');
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
    tokio::fs::create_dir_all(srv.cache_path.join(file_rel_folder))
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
        .https_only(true)
        .build()?)
}

fn connect_server(srv: &SymSrvSpec) -> anyhow::Result<reqwest::Client> {
    // Determine if the URL is a known URL that requires OAuth2 authorization.
    use url::{Host, Url};

    let url = Url::parse(&srv.server_url)
        .context(format!("invalid server URL: \"{}\"", &srv.server_url))?;
    match url.host() {
        Some(Host::Domain(d)) => {
            match d {
                // Azure DevOps
                d if d.ends_with("artifacts.visualstudio.com") || d.ends_with("dev.azure.com") => {
                    // Try and find the PAT for ADO from URL basic authentication.
                    let pat = url
                        .password()
                        .map(|p| p.to_string())
                        .context("ADO requires a PAT for authentication")?;

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

#[derive(Debug, Clone)]
pub struct SymSrv {
    spec: SymSrvSpec,
    client: reqwest::Client,
}

impl SymSrv {
    /// Attempt to connect to the specified symbol server.
    pub fn connect(spec: SymSrvSpec) -> anyhow::Result<Self> {
        Ok(Self {
            client: connect_server(&spec)?,
            spec,
        })
    }

    /// Retrieve the associated server specification from this connection.
    pub fn spec(&self) -> SymSrvSpec {
        self.spec.clone()
    }

    /// Attempt to find a single file in the symbol store associated with this context.
    ///
    /// If the file is found, its cache path will be returned.
    pub fn find_file(&self, name: &str, info: &SymFileInfo) -> Option<PathBuf> {
        let hash = info.to_string();

        // The file should be in each cache directory under the following path:
        // "<cache_dir>/<name>/<hash>/<name>"
        let path = PathBuf::from(&self.spec.cache_path)
            .join(name)
            .join(hash)
            .join(name);

        path.exists().then_some(path)
    }

    /// Download and cache a single file in the symbol store associated with this context,
    /// and then return its path on the local system.
    pub async fn download_file(
        &self,
        name: &str,
        info: &SymFileInfo,
    ) -> Result<PathBuf, DownloadError> {
        let hash = info.to_string();

        download_single(&self.client, &self.spec, None, name, &hash)
            .await
            .map(|r| r.1)
    }

    /// Download (displaying progress) and cache a single file in the symbol store associated with this context,
    /// and then return its path on the local system.
    pub async fn download_file_progress(
        &self,
        name: &str,
        info: &SymFileInfo,
        mp: &MultiProgress,
    ) -> Result<PathBuf, DownloadError> {
        let hash = info.to_string();

        download_single(&self.client, &self.spec, Some(mp), name, &hash)
            .await
            .map(|r| r.1)
    }
}
