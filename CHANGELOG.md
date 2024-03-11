# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.4](https://github.com/microsoft/pdblister/compare/v0.0.3...v0.0.4) - 2024-03-11

### Other
- Add release-plz workflow
- Bump to 0.0.3
- Updates to docs and misc. CLI improvements
- Bump h2 from 0.3.22 to 0.3.24
- Fix CI trigger
- Enable auto-merge for dependabot PRs
- Bump mio from 0.8.10 to 0.8.11
- Consolidate everything back into a single crate
- Swap to `clap::Parser` instead
- Delete the duplicate `Cargo.lock`; update deps
- Merge branch 'main' into dependabot/cargo/crates/bin/openssl-0.10.55
- Bump openssl from 0.10.48 to 0.10.55 in /crates/bin
- Add new `Request` error variant, add URL to invalid server URL message
- Fix download errors to be a bit more clear
- Bump h2 from 0.3.15 to 0.3.17
- Bump openssl from 0.10.44 to 0.10.48
- Bump openssl from 0.10.42 to 0.10.48 in /crates/bin
- Bump tokio from 1.23.1 to 1.24.2
- Bump tokio from 1.23.1 to 1.24.2 in /crates/bin
- Bump tokio from 1.21.2 to 1.23.1 in /crates/bin
- Bump tokio from 1.23.0 to 1.23.1
- Add the `tokio` feature for `indicatif` in the `symsrv` crate
- Remove FIXME comment
- Add a pdbstore command
- Merge branch 'main' into user/jusmoore/adopat
- Fix download stats reporting all files failed to download
- Touch up the README and add download_single docs
- Convert `SymSrvSpec::cache_path` to a `PathBuf`
- Use a more broad set of standard derives for public structures
- Add basic SymSrvSpec tests
- Split `SymContext` out into separate servers instead
- Pull out an independent `symsrv` crate
- Cut 0.0.2
- Undo the version bump
- Update README to remove ref to clean and time elapsed
- Exit with code 1 on failure
- Bump to 0.0.2, fixup cargo.toml ordering and update
- Add JSON output for download_single
- Update README
- Handle no argument case
- Convert over to clap for arg parsing
- Merge branch 'main' into sym_path_compat_and_errors
- Update src/symsrv.rs
- Improve errors around server strings to indicate what format is needed
- Ignore case when matching the start of the server path
- Show the causes of errors when failing to download PDBs
- Rework CI workflows
- Pull PE parsing code into its own module
- Update manifest for publish
- Use indicatif 0.17.1
- Attempt to use the PAT from the URL if provided
- Add `download_single` command for downloading symbols for specific exes. Fixes [#4](https://github.com/microsoft/pdblister/pull/4)
- Properly specify ADO PAT with leading colon
- Detect and panic if ADO returns a HTML response
- Remove patch-level specifications  for dependencies
- Create a `SymContext` to hold server connections for library users
- Add function `download_file` to download an invidual resource from a symbol server
- Cleanup and genericize some code to prep for library
- Enforce that ADO is accessed through HTTPS
- Add PAT login support for Azure DevOps
- Update dependencies
- Refactor out download logic into `download_single`
- Add support for `file.ptr` redirections. Fixes [#2](https://github.com/microsoft/pdblister/pull/2)
- Update dependencies
- Download PDBs to temporary files to avoid leaving truncated PDBs on-disk
- Use smoother progress bars
- Add support for multiple symbol servers
- Clean up some symsrv code; strongly type SymSrvList
- Update deps
- Use `zerocopy` to remove the last bits of unsafe
- Rename sym -> symsrv
- Properly size manifest progress bar
- Add faster download gif
- CI
- Update README.md
- Adjust progress bar sizing for small terminals
- Use multiprogress bars to report per-file download progress
- Anyhow-ize error reporting.
- Fix warnings.
- Print time elapsed with three decimal places
- Make the manifest progressbar more stylish
- Make `download_manifest` an async function
- Latest changes.
- Fix mutable variable warning
- Update dependencies
- Address clippy warnings and update tokio
- Add a progress bar and error output
- Implement symbol downloading without symchk.exe
- Async manifest generation
- Fix warnings about deprecated non-dyn traits
- Create LICENSE
- Updated usage in readme
- Added sympath
- Added filestore support
- Fixed some bugs. Updated documentation. Added a timer
- Added download functionality. Allowing for parallel downloads. Added command line parameters
- Markdown is impossible
- First commit
