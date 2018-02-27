# SmokeMonsterPacks
create smokemonster rom packs with the ability to read directy from and to an archive

## Goal
An alternative tool for building smokemonster rom packs based on the following source
https://github.com/SmokeMonsterPacks/EverDrive-Packs-Lists-Database

* Archive support using libarchive
* Multiple input sources
* Simultaneous output to folder and archive
* UTF-8 support

## TODO
* It would be nice to figure out windows support
* Writing to 7z seems to have some issues that need to be fixed (Reading from 7z seems fine)
* If you try to verify a zip file with unzip you get Extra-Field errors.  It verifies fine in 7z so this might be an issue with unzip and not libarchive

## Example usage

See full usage
```Bash
build_pack -h
```

Create an archive
```Bash
build_pack -d "database location" -i "input_dir" -i "input_file" -i "input_archive" -o "output_dir" -a "output_archive"
```

Verify an existing archive (This only verifies the file exists and has the correct hash.  It does not verify it is in the correct location)
```Bash
build_pack -d "database_location" -i "archive"
```
Verify an existing directory (This only verifies the file exists and has the correct hash.  It does not verify it is in the correct location)
```Bash
build_pack -d "database_location" -i "directory"
```
# Build

## Linux
A makefile is provided for building in linux  
Install libarchive  
cd to the directory and run 'make'  

## Windows
TBDT
