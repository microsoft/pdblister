use std::str::FromStr;
use std::error::Error;

extern crate futures;
extern crate reqwest;
extern crate tokio;

use futures::stream::StreamExt;

struct SymSrv {
    server: String,
    filepath: String,
}

impl FromStr for SymSrv {
    type Err = Box<dyn Error>;

    fn from_str(srv: &str) -> Result<Self, Self::Err> {
        // Split the path out by asterisks.
        let directives: Vec<&str> = srv.split("*").collect();

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

            },

            None => {
                return Err("Unsupported server string form".into());
            }
        };

        unreachable!();
    }
}

pub fn download_manifest(srvlist: String, files: Vec<String>) -> Result<(), Box<dyn Error>> {
    // First, parse the server string to figure out where we're supposed to fetch symbols from,
    // and where to.
    let srvstr: Vec<&str> = srvlist.split(";").collect();
    if srvstr.len() != 1 {
        return Err("Only one symbol server/path supported at this time.".into());
    }

    let srv: SymSrv = SymSrv::from_str(srvstr[0])?;

    // Create the directory first, if it does not exist.
    std::fs::create_dir_all(srv.filepath.clone())?;

    // http://patshaughnessy.net/2020/1/20/downloading-100000-files-using-async-rust
    // The following code is based off of the above blog post.
    let client = reqwest::Client::new();

    // Set up our asynchronous code block.
    // This block will be lazily executed when something awaits on it, such as the tokio thead pool below.
    let queries = futures::stream::iter(
        // Map the files vector using a closure, such that it's converted from a Vec<String>
        // into a Vec<Result<T, E>>
        files.into_iter().map(|line| {
            // Take explicit references to a few variables and move them into the async block.
            let client = &client;
            let srv = &srv;

            async move {
                // Break out the filename into the separate components.
                let el: Vec<&str> = line.split(",").collect();
                if el.len() != 3 {
                    panic!("Invalid manifest line encountered: \"{}\"", line);
                }
                
                // Create the directory tree.
                std::fs::create_dir_all(format!("{}/{}/{}", srv.filepath, el[0], el[1]).to_string())?;

                let pdbpath = format!("{}/{}/{}", el[0], el[1], el[0]);

                // Check to see if the file already exists. If so, skip it.
                if std::path::Path::new(&format!("{}/{}", srv.filepath, pdbpath)).exists() {
                    return Ok(());
                }

                println!("{}/{}", el[0], el[1]);

                // Attempt to retrieve the file.
                let req = client.get::<&str>(&format!("{}/{}", srv.server, pdbpath).to_string()).send().await?;
                if req.status() != 200 {
                    return Err(format!("Code {}", req.status()).into());
                }

                // Create the output file.
                let mut file = tokio::fs::File::create(format!("{}/{}", srv.filepath, pdbpath).to_string()).await?;
                tokio::io::copy(&mut req.bytes().await?.as_ref(), &mut file).await?;

                return Ok(());
            }
        })
    ).buffer_unordered(64).collect::<Vec<Result<(), Box<dyn Error>>>>();

    // N.B: The buffer_unordered bit above allows us to feed in 64 requests at a time to tokio.
    // That way we don't exhaust system resources in the networking stack or filesystem.

    // Start up a tokio runtime and run through the requests.
    let mut rt = tokio::runtime::Runtime::new()?;
    rt.block_on(queries);

    return Ok(());
}