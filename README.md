# Summary

This is a tiny **unofficial** project meant to be a quick alternative to symchk for
miscellaneous tasks, such as generating manifests and downloading symbols. This
mimics symchk of the form `symchk /om manifest /r <path>` but only looks for MZ/PE files.

Due to symchk doing some weird things it can often crash or get stuck in
infinite loops. Thus this is a stricter (and much faster) alternative.

The output manifest is compatible with symchk. If you want to use symchk
in lieu of this tool, use `symchk /im manifest /s <symbol path>`

⚠️ Note: This tool is **unstable**! The CLI interface may change at any point, **without warning**.
If you need programmatic stability (e.g. for automation), please pin your install to a specific revision.

Check out how fast this tool is:
![](docs/images/download.gif)

# Quick Start

```
# On your target
> cargo run --release -- manifest C:\Windows\System32

# On an online machine
> cargo run --release -- download SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

## Downloading a single PDB file
```
> cargo run --release -- download_single SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols C:\Windows\System32\notepad.exe
```

# Future

Randomizing the order of the files in the manifest would make downloads more
consistant by not having any filesystem locality bias in the files.

Deduping the files in the manifests could also help, but this isn't a big
deal *shrug*

We could potentially offer a symchk-compatible subcommand: [#5](https://github.com/microsoft/pdblister/issues/5)

A "server mode" could be implemented so that other tools written in different languages could take advantage of our functionality: [#7](https://github.com/microsoft/pdblister/issues/7)

# Performance

This tool tries to do everything in memory if it can. Lists all files first
then does all the parsing (this has random accesses to files without mapping so
it could be improved, but it doesn't really seem to be an issue, this random
access only occurs if it sees an MZ and PE header and everything is valid).

It also generates the manifest in memory and dumps it out in one swoop, this is
one large bottleneck original symchk has.

Then for downloads it chomps through a manifest file asynchronously, at up to
16 files at the same time! The original `symchk` only peaks at about 3-4 Mbps
of network usage, but this tool saturates my internet connection at
400 Mbps.
