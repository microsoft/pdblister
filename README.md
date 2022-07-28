# Summary

This is a tiny project to be a quick alternative to symchk for generating
manifests. This mimics symchk of the form `symchk /om manifest /r <path>`
but only looks for MZ/PE files.

Due to symchk doing some weird things it can often crash or get stuck in
infinite loops. Thus this is a stricter (and much faster) alternative.

The output manifest is compatible with symchk. If you want to use symchk
in lieu of this tool, use `symchk /im manifest /s <symbol path>`

![](docs/images/download.gif)

# Usage

Usage:

    pdblister [manifest | download | download_single | filestore | clean] <filepath>
 
    === Create manifest === 
    
        pdblister manifest <filepath>

        This command takes in a filepath to recursively search for files that
        have a corresponding PDB. This creates a file called `manifest` which
        is compatible with symchk.
        
        For example `pdblister manifest C:\\windows` will create `manifest`
        containing all of the PDB signatures for all of the files in
        C:\\windows.

    === Download from manifest ===

        pdblister download <sympath>

        This command takes no parameters. It simply downloads all the PDBs
        specified in the `manifest` file.

    === Download single executable ===

        pdblister download_single <sympath> <exepath>

        This command will take a symbol server URL and executable path, and
        use the symbol server to download the PDB file for the executable to
        the cache directory.

    === Create a file store ===

        pdblister filestore <filepath>

        This command recursively walks filepath to find all PEs. Any PE file
        that is found is copied to the local directory 'filestore' using the
        layout that symchk.exe uses to store normal files. This is used to
        create a store of all PEs (such as .dlls), which can be used by a
        kernel debugger to read otherwise paged out memory by downloading the
        original PE source file from this filestore.

        To use this filestore simply merge the contents in with a symbol
        store/cache path. We keep it separate in this tool just to make it
        easier to only get PDBs if that's all you really want.

    === Clean ===

        pdblister clean

        This command removes the `manifest` file as well as the symbol folder
        and the filestore folder

# Future

More configuration could be done through command line parameters. Such as
number of threads for downloads and symbol paths.

Randomizing the order of the files in the manifest would make downloads more
consistant by not having any filesystem locality bias in the files.

Deduping the files in the manifests could also help, but this isn't a big
deal *shrug*

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

Look how damn fast this stuff is!

```
On an offline machine:

PS C:\users\pleb\Downloads> .\pdblister.exe clean
Time elapsed: 0 seconds
PS C:\users\pleb\Downloads> .\pdblister.exe manifest C:\
Generating file listing...
Done!
Parsed 398632 of 398632 files (23051 pdbs)
Time elapsed: 104 seconds

On an online machine:
C:\dev\pdblister>cargo run --release download
    Finished release [optimized] target(s) in 0.0 secs
     Running `target\release\pdblister.exe download`
Trying to download 23051 PDBs
Time elapsed: 120 seconds
```

