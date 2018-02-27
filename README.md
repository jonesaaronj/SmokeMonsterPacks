# SmokeMonsterPacks
smokemonster rom packs with archive support

## Goal
An alternative tool for building smokemonster rom packs based on the following source
https://github.com/SmokeMonsterPacks/EverDrive-Packs-Lists-Database

* Archive support using libarchive
* Multiple input sources
* Simultaneous output to folder and archive
* UTF-8 support

## Example usage

Create an archive
```Bash
build_pack -d "database location" -i "input_dir" -i "input_file" -i "input_archive" -o "output_dir" -a "output_archive"
```

Verify an archive
```Bash
build_pack -d "database_location" -i "archive"
```
Verify a directory
```Bash
build_pack -d "database_location" -i "directory"
```
