`py1packer` is a python script that packs files from a directory into a single, self-extracting python script.

### features
* packs files from a specified directory into a single python script.
* supports overwriting policies (`skip`, `increment`).
* can recursively pack subdirectories.
* allows excluding specific files or directories using patterns.
* includes a `dry-run` mode to preview actions without actual file operations.
* can delete original files after packing.
* provides verbose logging for debugging.

### usage
```bash
python3 packer.py <directory_to_pack> [options]
```

### options
* `-o, --output <file>`: specify the output script name (default: `packed.py`).
* `--overwrite {skip,increment}`: set the overwrite policy for the output file (default: `increment`).
* `-r, --recursive`: include subdirectories when packing.
* `-e, --exclude <paths>`: exclude relative paths (files or directories) from packing.
* `--delete-packer`: delete original files and empty directories after packing.
* `--dry-run`: show what would be done without actually writing or deleting.
* `-v, --verbose`: enable debug mode for more detailed logging.

### example
pack a directory named `my_files` recursively into `my_packed_app.py`, deleting originals:
```bash
python3 packer.py my_files -o my_packed_app.py -r --delete-packer
```

to extract files from `my_packed_app.py`:
```bash
python3 my_packed_app.py
```
