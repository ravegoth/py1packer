#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import os
import sys
from itertools import count


class PackerError(Exception):
    pass


def normalize_archive_path(path):
    normalized = os.path.normpath(str(path)).replace("\\", "/").strip("/")
    return "." if normalized in ("", ".") else normalized


def path_is_inside(path, root):
    try:
        path_abs = os.path.abspath(path)
        root_abs = os.path.abspath(root)
        return os.path.commonpath([path_abs, root_abs]) == root_abs
    except (OSError, ValueError):
        return False


def normalize_excludes(exclude, root_dir=None):
    patterns = []
    for item in exclude or []:
        if item is None:
            continue
        raw = str(item).strip()
        if not raw:
            continue
        if root_dir and os.path.isabs(raw) and path_is_inside(raw, root_dir):
            raw = os.path.relpath(raw, root_dir)
        patterns.append(normalize_archive_path(raw))
    return sorted(set(patterns))


def is_excluded(relative_path, patterns):
    path = normalize_archive_path(relative_path)
    for pattern in patterns:
        if pattern == ".":
            return True
        prefix = pattern.rstrip("/") + "/"
        if path == pattern or path.startswith(prefix):
            return True
    return False


def find_output_path(base, policy):
    if not os.path.exists(base):
        return base
    if policy == "skip":
        raise PackerError(f"output exists and policy=skip: {base}")
    if policy == "increment":
        name, ext = os.path.splitext(base)
        for i in count(2):
            candidate = f"{name}_{i}{ext}"
            if not os.path.exists(candidate):
                return candidate
    raise PackerError(f"unknown overwrite policy: {policy}")


def gather_files(root_dir, exclude, recursive):
    patterns = normalize_excludes(exclude)
    collected_files = []
    collected_dirs = set()

    for dirpath, dirs, files in os.walk(root_dir, topdown=True):
        dirs.sort()
        files.sort()

        if recursive:
            kept_dirs = []
            for dirname in dirs:
                rel_dir = normalize_archive_path(os.path.relpath(os.path.join(dirpath, dirname), root_dir))
                if is_excluded(rel_dir, patterns):
                    logging.debug("excluded directory %s", rel_dir)
                    continue
                kept_dirs.append(dirname)
                collected_dirs.add(rel_dir)
            dirs[:] = kept_dirs
        else:
            dirs[:] = []

        for filename in files:
            full_path = os.path.join(dirpath, filename)
            rel_file = normalize_archive_path(os.path.relpath(full_path, root_dir))
            if is_excluded(rel_file, patterns):
                logging.debug("excluded file %s", rel_file)
                continue
            collected_files.append(rel_file)
            parent = os.path.dirname(rel_file).replace("\\", "/")
            if parent and parent != ".":
                collected_dirs.add(parent)

    directories = sorted(collected_dirs, key=lambda item: (item.count("/"), item))
    return collected_files, directories


def encode_files(files, root):
    result = {}
    for rel in files:
        path = os.path.join(root, *rel.split("/"))
        try:
            with open(path, "rb") as handle:
                result[rel] = base64.b64encode(handle.read()).decode("ascii")
            logging.debug("encoded %s", rel)
        except OSError as exc:
            logging.warning("could not encode %s: %s", rel, exc)
    return result


def build_extractor(data_map, directories_to_create, output):
    directories = sorted(set(normalize_archive_path(path) for path in directories_to_create if normalize_archive_path(path) != "."))
    data = {normalize_archive_path(path): value for path, value in data_map.items()}
    lines = [
        "#!/usr/bin/env python3",
        "import base64",
        "import logging",
        "import os",
        "import sys",
        f"DATA = {json.dumps(data, sort_keys=True)}",
        f"DIRECTORIES = {json.dumps(directories)}",
        "logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)",
        "",
        "def archive_target(relative_path):",
        "    normalized = relative_path.replace('\\\\', '/')",
        "    parts = [part for part in normalized.split('/') if part not in ('', '.')]",
        "    if not parts or any(part == '..' for part in parts):",
        "        raise ValueError(f'unsafe path: {relative_path}')",
        "    return os.path.join(*parts)",
        "",
        "def main():",
        "    failures = 0",
        "    if DIRECTORIES:",
        "        logging.info('Creating directories...')",
        "    for relative_dir in DIRECTORIES:",
        "        try:",
        "            target_dir = archive_target(relative_dir)",
        "            os.makedirs(target_dir, exist_ok=True)",
        "            logging.info(f'  Created directory: {relative_dir}')",
        "        except Exception as exc:",
        "            logging.error(f'  Could not create directory {relative_dir}: {exc}')",
        "            failures += 1",
        "    logging.info('Extracting files...')",
        "    if not DATA:",
        "        logging.info('  No files to extract.')",
        "    for relative_file, payload in DATA.items():",
        "        try:",
        "            target_file = archive_target(relative_file)",
        "            parent = os.path.dirname(target_file)",
        "            if parent:",
        "                os.makedirs(parent, exist_ok=True)",
        "            with open(target_file, 'wb') as handle:",
        "                handle.write(base64.b64decode(payload))",
        "            logging.info(f'  Extracted: {relative_file}')",
        "        except Exception as exc:",
        "            logging.error(f'  Could not extract {relative_file}: {exc}')",
        "            failures += 1",
        "    if failures:",
        "        logging.error(f'Extraction completed with {failures} error(s).')",
        "        sys.exit(1)",
        "    logging.info('Extraction complete.')",
        "",
        "if __name__ == '__main__':",
        "    main()",
    ]
    try:
        parent = os.path.dirname(os.path.abspath(output))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
        logging.info("wrote extractor to %s", output)
        try:
            os.chmod(output, 0o755)
        except OSError as exc:
            logging.warning("could not set executable permission on %s: %s", output, exc)
    except OSError as exc:
        raise PackerError(f"could not write to output file {output}: {exc}") from exc


def delete_originals_packer(root, files_to_delete, dirs_to_delete):
    logging.info("cleaning up originals after packing...")
    for rel in files_to_delete:
        path = os.path.join(root, *normalize_archive_path(rel).split("/"))
        try:
            os.remove(path)
            logging.info("deleted file %s", rel)
        except FileNotFoundError:
            continue
        except OSError as exc:
            logging.warning("could not delete file %s: %s", rel, exc)

    for rel_dir in sorted(dirs_to_delete, key=lambda item: (item.count("/"), item), reverse=True):
        path = os.path.join(root, *normalize_archive_path(rel_dir).split("/"))
        if os.path.abspath(path) == os.path.abspath(root):
            continue
        try:
            os.rmdir(path)
            logging.info("removed empty directory %s", rel_dir)
        except OSError as exc:
            logging.debug("could not remove directory %s: %s", rel_dir, exc)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Pack a directory into a self-extracting script")
    parser.add_argument("directory", help="directory to pack")
    parser.add_argument("-o", "--output", default="packed.py", help="output script")
    parser.add_argument("--overwrite", choices=["skip", "increment"], default="increment", help="overwrite policy")
    parser.add_argument("-r", "--recursive", action="store_true", help="include subdirectories")
    parser.add_argument("-e", "--exclude", nargs="*", default=[], help="relative files or directories to exclude")
    parser.add_argument("--delete-packer", action="store_true", help="delete packed originals after writing the extractor")
    parser.add_argument("--dry-run", action="store_true", help="show actions without writing or deleting")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


def prepare_excludes(root, output, excludes):
    root_abs = os.path.abspath(root)
    prepared = normalize_excludes(excludes, root_abs)
    for candidate in (output, __file__):
        candidate_abs = os.path.abspath(candidate)
        if candidate_abs != root_abs and path_is_inside(candidate_abs, root_abs):
            prepared.append(normalize_archive_path(os.path.relpath(candidate_abs, root_abs)))
    return sorted(set(prepared))


def pack_directory(root, output, overwrite="increment", recursive=False, exclude=None, dry_run=False, delete_packer=False):
    if not os.path.isdir(root):
        raise NotADirectoryError(root)

    excludes = prepare_excludes(root, output, exclude or [])
    logging.debug("final exclude patterns: %s", excludes)
    files_to_pack, dirs_to_create = gather_files(root, excludes, recursive)
    logging.info("found %d files and %d directories to include", len(files_to_pack), len(dirs_to_create))
    logging.debug("files to pack: %s", files_to_pack)
    logging.debug("directories to include: %s", dirs_to_create)

    if dry_run:
        logging.info("dry-run: no files written or deleted")
        return {"output": None, "files": files_to_pack, "directories": dirs_to_create, "excludes": excludes}

    final_output = find_output_path(output, overwrite)
    encoded = encode_files(files_to_pack, root)
    build_extractor(encoded, dirs_to_create, final_output)
    logging.info("packed into %s", final_output)

    if delete_packer:
        delete_originals_packer(root, list(encoded.keys()), dirs_to_create)

    return {"output": final_output, "files": files_to_pack, "directories": dirs_to_create, "excludes": excludes}


def main(argv=None):
    args = parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    try:
        pack_directory(
            args.directory,
            args.output,
            overwrite=args.overwrite,
            recursive=args.recursive,
            exclude=args.exclude,
            dry_run=args.dry_run,
            delete_packer=args.delete_packer,
        )
    except NotADirectoryError:
        logging.error("not a directory: %s", args.directory)
        sys.exit(1)
    except PackerError as exc:
        logging.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
