#![allow(unknown_lints)]
#![warn(clippy::all)]
#![allow(clippy::needless_return)]

use std::str::FromStr;

extern crate futures;
extern crate indicatif;
extern crate reqwest;
extern crate tokio;

use indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle};

use anyhow::Context;
use futures::stream::StreamExt;
use tokio::io::AsyncWriteExt;

enum DownloadStatus {
    AlreadyExists,
    DownloadedOk,
}

struct SymSrv {
    server: String,
    filepath: String,
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
                        server: directives[2].to_string(),
                        filepath: directives[1].to_string(),
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

fn parse_servers(srvstr: String) -> anyhow::Result<Vec<SymSrv>> {
    let server_list: Vec<&str> = srvstr.split(';').collect();
    if server_list.is_empty() {
        anyhow::bail!("Invalid server string");
    }

    server_list
        .into_iter()
        .map(|symstr| symstr.parse::<SymSrv>())
        .collect()
}

pub async fn download_manifest(srvstr: String, files: Vec<String>) -> anyhow::Result<()> {
    // First, parse the server string to figure out where we're supposed to fetch symbols from,
    // and where to.
    let srvs = parse_servers(srvstr)?;
    if srvs.len() != 1 {
        anyhow::bail!("Only one symbol server/path supported at this time");
    }

    let srv = &srvs[0];

    // Create the directory first, if it does not exist.
    std::fs::create_dir_all(srv.filepath.clone()).context("Failed to create symbol directory")?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let client = reqwest::Client::new();

    let m = MultiProgress::new();

    // Create a progress bar.
    let pb = m.add(ProgressBar::new(files.len() as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:.cyan/blue} {pos:>10}/{len:10} ({eta}) {msg}")
            .progress_chars("##-"),
    );

    // Set up our asynchronous code block.
    // This block will be lazily executed when something awaits on it, such as the tokio thread pool below.
    let queries = futures::stream::iter(
        // Map the files vector using a closure, such that it's converted from a Vec<String>
        // into a Vec<Result<T, E>>
        files.into_iter().map(|line| {
            // Take explicit references to a few variables and move them into the async block.
            let client = &client;
            let srv = &srv;
            let pb = pb.clone();
            let m = &m;

            async move {
                // Break out the filename into the separate components.
                let el: Vec<&str> = line.split(',').collect();
                if el.len() != 3 {
                    panic!("Invalid manifest line encountered: \"{}\"", line);
                }

                pb.inc(1);

                // Create the directory tree.
                tokio::fs::create_dir_all(format!("{}/{}/{}", srv.filepath, el[0], el[1])).await?;

                let pdbpath = format!("{}/{}/{}", el[0], el[1], el[0]);

                // Check to see if the file already exists. If so, skip it.
                if std::path::Path::new(&format!("{}/{}", srv.filepath, pdbpath)).exists() {
                    return Ok(DownloadStatus::AlreadyExists);
                }

                // Attempt to retrieve the file.
                let mut req = client
                    .get::<&str>(&format!("{}/{}", srv.server, pdbpath).to_string())
                    .send()
                    .await?;
                if req.status() != 200 {
                    return Err(anyhow::anyhow!("File {} - Code {}", pdbpath, req.status()));
                }

                let dl_pb = m.add(ProgressBar::new(req.content_length().unwrap()));
                dl_pb.set_style(ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:.cyan/blue} {bytes:>10}/{total_bytes:10} {msg}  ({eta})")
                    .progress_chars("##-")
                    .on_finish(ProgressFinish::AndClear)
                );
                dl_pb.set_message(format!("{}/{}", el[1], el[0]));

                // Create the output file.
                let mut file =
                    tokio::fs::File::create(format!("{}/{}", srv.filepath, pdbpath).to_string())
                        .await?;

                // N.B: We use this in lieu of tokio::io::copy so we can update the download progress.
                while let Some(chunk) = req.chunk().await? {
                    dl_pb.inc(chunk.len() as u64);
                    file.write(&chunk).await?;
                }

                return Ok(DownloadStatus::DownloadedOk);
            }
        }),
    )
    .buffer_unordered(16)
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
        Err(res) => {
            eprintln!("{}", res);
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
