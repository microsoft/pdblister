pub mod blocking;
pub mod nonblocking;

use thiserror::Error;

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
