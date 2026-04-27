# Py1Packer

Py1Packer packs a directory into one self-extracting Python script. It includes a command-line interface and a dark Tkinter GUI.

## Features

- Packs files into a standalone Python extractor.
- Supports recursive and top-level-only packing.
- Supports `skip` and `increment` overwrite policies.
- Excludes relative files or folders.
- Runs dry runs before writing anything.
- Can delete packed originals after a successful package write.
- Preserves empty included directories.
- Creates parent folders during extraction.

## GUI

```bash
python py1packer_gui.py
```

The GUI provides source/output pickers, dark themed controls, exclusion helpers, dry-run preview, progress state, and color-coded logs.

## CLI

```bash
python py1packer.py <directory_to_pack> [options]
```

## Options

- `-o, --output <file>`: output script path. Defaults to `packed.py`.
- `--overwrite {skip,increment}`: output collision behavior. Defaults to `increment`.
- `-r, --recursive`: include subdirectories.
- `-e, --exclude <paths>`: relative files or directories to exclude.
- `--delete-packer`: delete packed originals after writing the extractor.
- `--dry-run`: preview what would be packed without writing or deleting.
- `-v, --verbose`: enable debug logging.

## Example

```bash
python py1packer.py my_files -o my_packed_app.py -r --delete-packer
python my_packed_app.py
```
