# XPEID

`XPEID` is a small scan engine that uses PEiD `userdb.txt` signatures to detect packers/protectors in PE files.

## Usage

1. Place your PEiD `userdb.txt` in the module folder, for example:

   ```txt
   _mylibs/XPEID/peid/userdb.txt
   ```

2. Load the database using `XPEID::loadDatabase(path)` and call `scanFile()` or `scanDevice()`.

## Project structure

- `xpeid.h` / `xpeid.cpp`: the scan engine implementation.
- `xpeid.cmake`: CMake source list used by higher-level projects.

## Notes

- The parser expects `userdb.txt` lines to contain a signature name followed by a hex signature pattern.
- Line comments beginning with `;`, `#`, or `//` are ignored.
