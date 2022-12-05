use std::path::PathBuf;

use crate::{nonblocking, DownloadError, SymFileInfo, SymSrvSpec};

use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct SymSrv {
    inner: nonblocking::SymSrv,
    rt: Runtime,
}

impl SymSrv {
    pub fn new(spec: SymSrvSpec) -> anyhow::Result<Self> {
        Ok(Self {
            inner: nonblocking::SymSrv::connect(spec)?,
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
        })
    }

    /// Attempt to find a single file in the symbol store associated with this context.
    ///
    /// If the file is found, its cache path will be returned.
    pub fn find_file(&self, name: &str, info: &SymFileInfo) -> Option<PathBuf> {
        self.inner.find_file(name, info)
    }

    /// Download and cache a single file in the symbol store associated with this context,
    /// and then return its path on the local system.
    pub fn download_file(&self, name: &str, info: &SymFileInfo) -> Result<PathBuf, DownloadError> {
        self.rt.block_on(self.inner.download_file(name, info))
    }
}
