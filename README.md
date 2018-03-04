# SmokeMonsterPacks
Create smokemonster rom packs from a database file and a collection of roms with the ability to read directy from and/or to an archive (7z, zip, ...)

## Goal
An alternative tool for building smokemonster rom packs based on the following source
https://github.com/SmokeMonsterPacks/EverDrive-Packs-Lists-Database

+ Archive support using libarchive
  + Currently zip, rar, and 7z are supported for input (Single level deep archives only, Can't read a zip inside a zip for example)
  + Currently zip and 7z are supported for output
+ Multiple input sources
+ Simultaneous output to folder and archive
+ UTF-8 support

## TODO
* It would be nice to add windows and osx support.
  * investigate building in windows with mingw, libarchive, and gnulib. (any advice here is welcome)
  * investigate replacing linux specific things like ftw.
* Support more input and output archive types.  What would anyone want besides 7z and zip?
* Writing very large 7z files breaks on my small pc (AMD E-350, 4gb) but works fine on my server (AMD-FX, 32gb).  Might investigate setting 7z compression dictionary size in libarchive.
* If you try to verify a zip file with unzip you get Extra-Field errors.  It verifies fine in 7z so this might be an issue with unzip and not libarchive

## Example usage

See full usage
```Bash
smp -h
```

Create a zip archive and also output to a directory
```Bash
smp -d "database_location" -i "input_dir" -i "input_file" -i "input_archive" -o "output_dir" -a "output_archive.zip"
```

Verify an existing archive (This only verifies the file exists and has the correct hash.  It does not verify it is in the correct location)
```Bash
smp -d "database_location" -i "archive.7z"
```
Verify an existing directory (This only verifies the file exists and has the correct hash.  It does not verify it is in the correct location)
```Bash
smp -d "database_location" -i "directory"
```

Create a database file from a directory
```
smp -D "databse_location" -P "directory"
```

Create a database file from an archive
```
smp -D "databse_location" -A "archive"
```

# Build

## Linux
A makefile is provided for building in linux  
Install libarchive  
cd to the directory and run 'make'  

## Windows
TBDT
