#![allow(unknown_lints)]
#![warn(clippy::all)]
#![allow(clippy::needless_return)]

use std::str::FromStr;

extern crate futures;
extern crate indicatif;
extern crate reqwest;
extern crate tokio;

use indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle};

use futures::stream::StreamExt;
use tokio::io::AsyncWriteExt;

enum DownloadStatus {
    AlreadyExists,
    DownloadedOk,
}

enum RemoteFileType {
    /// HTTP-accessible URL (with a response already received)
    Url(reqwest::Response),
    /// Path on a network share
    Path(String),
}

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

pub struct SymSrvList(Box<[SymSrv]>);

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

pub async fn download_manifest(srvstr: String, files: Vec<String>) -> anyhow::Result<()> {
    // First, parse the server string to figure out where we're supposed to fetch symbols from,
    // and where to.
    let srvs = SymSrvList::from_str(&srvstr)?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let client = reqwest::Client::new();

    let m = MultiProgress::new();

    // Create a progress bar.
    let pb = m.add(ProgressBar::new(files.len() as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>10}/{len:10} ({eta}) {msg}")
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    // Set up our asynchronous code block.
    // This block will be lazily executed when something awaits on it, such as the tokio thread pool below.
    let queries = futures::stream::iter(
        // Map the files vector using a closure, such that it's converted from a Vec<String>
        // into a Vec<Result<T, E>>
        files.into_iter().map(|line| {
            // Take explicit references to a few variables and move them into the async block.
            let client = &client;
            let srvs = &srvs;
            let pb = pb.clone();
            let m = &m;

            async move {
                // Break out the filename into the separate components.
                // name,UUID,version
                let el: Vec<&str> = line.split(',').collect();
                if el.len() != 3 {
                    panic!("Invalid manifest line encountered: \"{}\"", line);
                }

                pb.inc(1);

                // e.g: "ntkrnlmp.pdb/32C1A669D5FFEFD41091F636CFDB6E991"
                let pdbpath = format!("{}/{}", el[0], el[1]);

                for srv in srvs.0.iter() {
                    // The name of the file on the local filesystem
                    let file_name = format!("{}/{}/{}", srv.cache_path, pdbpath, el[0]);
                    // The path to the file's folder on the remote server
                    let file_folder_url = format!("{}/{}", srv.server_url, pdbpath);

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
                            .get::<&str>(&format!("{}/{}", file_folder_url, el[0]))
                            .send()
                            .await?;
                        if pdb_req.status().is_success() {
                            RemoteFileType::Url(pdb_req)
                        } else {
                            // Try a `file.ptr` redirection URL
                            let fileptr_req = client.get::<&str>(&format!("{}/file.ptr", file_folder_url)).send().await?;
                            if !fileptr_req.status().is_success() {
                                // Attempt another server instead
                                continue;
                            }
                            
                            let url = fileptr_req.text().await?;

                            // FIXME: Would prefer not to unwrap the iterator results...
                            let mut url_iter = url.split(":");
                            let url_type = url_iter.next().unwrap();
                            let url = url_iter.next().unwrap();

                            match url_type {
                                "PATH" => {
                                    RemoteFileType::Path(url.to_string())
                                }

                                "MSG" => {
                                    // Try another server.
                                    continue;
                                }

                                typ => {
                                    unimplemented!("Unknown symbol redirection pointer type {typ}!\n{url_type}:{url}");
                                }
                            }
                        }
                    };

                    // Create the directory tree.
                    tokio::fs::create_dir_all(format!("{}/{}/{}", srv.cache_path, el[0], el[1])).await?;

                    match remote_file {
                        RemoteFileType::Url(mut res) => {
                            // N.B: If the server sends us a content-length header, use it to display a progress bar.
                            // Otherwise, just display a spinner progress bar.
                            let dl_pb = match res.content_length() {
                                Some(len) => {
                                    let dl_pb = m.add(ProgressBar::new(len));
                                    dl_pb.set_style(ProgressStyle::default_bar()
                                        .template("[{elapsed_precise}] {bar:.cyan/blue} {bytes:>10}/{total_bytes:10} {wide_msg}")
                                        .progress_chars("█▉▊▋▌▍▎▏  ")
                                        .on_finish(ProgressFinish::AndClear)
                                    );

                                    dl_pb
                                },

                                None => {
                                    let dl_pb = m.add(ProgressBar::new_spinner());
                                    dl_pb.set_style(ProgressStyle::default_bar()
                                        .template("[{elapsed_precise}] {spinner} {bytes_per_sec:>10} {wide_msg}")
                                        .on_finish(ProgressFinish::AndClear)
                                    );
                                    dl_pb.enable_steady_tick(5);

                                    dl_pb
                                }
                            };

                            dl_pb.set_message(format!("{}/{}", el[1], el[0]));

                            // Create the output file.
                            let mut file =
                                tokio::fs::File::create(&file_name_tmp)
                                    .await?;

                            // N.B: We use this in lieu of tokio::io::copy so we can update the download progress.
                            while let Some(chunk) = res.chunk().await? {
                                dl_pb.inc(chunk.len() as u64);
                                file.write(&chunk).await?;
                            }

                            // Rename the temporary copy to the final name
                            tokio::fs::rename(&file_name_tmp, file_name).await?;

                            return Ok(DownloadStatus::DownloadedOk);
                        }

                        RemoteFileType::Path(path) => {
                            // Attempt to open the file via the filesystem.
                            let remote_file = tokio::fs::File::open(path).await?;
                            let metadata = remote_file.metadata().await?;

                            let dl_pb = m.add(ProgressBar::new(metadata.len()));
                            dl_pb.set_style(ProgressStyle::default_bar()
                                .template("[{elapsed_precise}] {bar:.cyan/blue} {bytes:>10}/{total_bytes:10} {wide_msg}")
                                .progress_chars("█▉▊▋▌▍▎▏  ")
                                .on_finish(ProgressFinish::AndClear)
                            );

                            dl_pb.set_message(format!("{}/{}", el[1], el[0]));

                            // Create the output file.
                            let mut file =
                                tokio::fs::File::create(&file_name_tmp).await?;

                            tokio::io::copy(&mut dl_pb.wrap_async_read(remote_file), &mut file).await?;

                            // Rename the temporary copy to the final name
                            tokio::fs::rename(&file_name_tmp, file_name).await?;
                        }
                    }
                }

                return Err(anyhow::anyhow!("File {} - Code 404", pdbpath));
            }
        }),
    )
    .buffer_unordered(32)
    .collect::<Vec<anyhow::Result<DownloadStatus>>>();

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
