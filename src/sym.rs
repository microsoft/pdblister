#![allow(unknown_lints)]
#![warn(clippy::all)]
#![allow(clippy::needless_return)]

use std::error::Error;
use std::str::FromStr;

extern crate futures;
extern crate indicatif;
extern crate reqwest;
extern crate tokio;

use indicatif::{ProgressBar, ProgressStyle};

use futures::stream::StreamExt;

struct SymSrv {
    server: String,
    filepath: String,
}

impl FromStr for SymSrv {
    type Err = Box<dyn Error>;

    fn from_str(srv: &str) -> Result<Self, Self::Err> {
        // Split the path out by asterisks.
        let directives: Vec<&str> = srv.split('*').collect();

        // Ensure that the path starts with `SRV*` - the only form we currently support.
        match directives.first() {
            // Simply exit the match statement if the directive is "SRV"
            Some(x) => {
                if "SRV" == *x {
                    if directives.len() != 3 {
                        return Err("".into());
                    }

                    // Alright, the directive is of the proper form. Return the server and filepath.
                    return Ok(SymSrv {
                        server: directives[2].to_string(),
                        filepath: directives[1].to_string(),
                    });
                }
            }

            None => {
                return Err("Unsupported server string form".into());
            }
        };

        unreachable!();
    }
}

fn parse_servers(srvstr: String) -> Result<Vec<SymSrv>, Box<dyn Error>> {
    let server_list: Vec<&str> = srvstr.split(';').collect();
    if server_list.is_empty() {
        return Err("Invalid server string!".into());
    }

    let symbol_servers = server_list
        .into_iter()
        .map(|symstr| {
            return symstr.parse::<SymSrv>();
        })
        .collect();

    return symbol_servers;
}

pub fn download_manifest(srvstr: String, files: Vec<String>) -> Result<(), Box<dyn Error>> {
    // First, parse the server string to figure out where we're supposed to fetch symbols from,
    // and where to.
    let srvs = parse_servers(srvstr)?;
    if srvs.len() != 1 {
        return Err("Only one symbol server/path supported at this time.".into());
    }

    let srv = &srvs[0];

    // Create the directory first, if it does not exist.
    std::fs::create_dir_all(srv.filepath.clone())?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let client = reqwest::Client::new();

    // Create a progress bar.
    let pb = ProgressBar::new(files.len() as u64);

    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} ({eta}) {msg}")
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

            async move {
                // Break out the filename into the separate components.
                let el: Vec<&str> = line.split(',').collect();
                if el.len() != 3 {
                    panic!("Invalid manifest line encountered: \"{}\"", line);
                }

                // Create the directory tree.
                std::fs::create_dir_all(format!("{}/{}/{}", srv.filepath, el[0], el[1]))?;

                let pdbpath = format!("{}/{}/{}", el[0], el[1], el[0]);

                // Check to see if the file already exists. If so, skip it.
                if std::path::Path::new(&format!("{}/{}", srv.filepath, pdbpath)).exists() {
                    pb.inc(1);
                    return Ok(());
                }

                // println!("{}/{}", el[0], el[1]);
                pb.set_message(format!("{}/{}", el[1], el[0]).as_str());
                pb.inc(1);

                // Attempt to retrieve the file.
                let req = client
                    .get::<&str>(&format!("{}/{}", srv.server, pdbpath).to_string())
                    .send()
                    .await?;
                if req.status() != 200 {
                    return Err(format!("File {} - Code {}", pdbpath, req.status()).into());
                }

                // Create the output file.
                let mut file =
                    tokio::fs::File::create(format!("{}/{}", srv.filepath, pdbpath).to_string())
                        .await?;
                tokio::io::copy(&mut req.bytes().await?.as_ref(), &mut file).await?;

                return Ok(());
            }
        }),
    )
    .buffer_unordered(64)
    .collect::<Vec<Result<(), Box<dyn Error>>>>();

    // N.B: The buffer_unordered bit above allows us to feed in 64 requests at a time to tokio.
    // That way we don't exhaust system resources in the networking stack or filesystem.

    // Start up a tokio runtime and run through the requests.
    let rt = tokio::runtime::Runtime::new()?;
    let output = rt.block_on(queries);

    pb.finish();

    // Collect output results.
    output.iter().for_each(|x| match x {
        Err(res) => {
            println!("{}", res);
        }

        Ok(_) => (),
    });

    return Ok(());
}
