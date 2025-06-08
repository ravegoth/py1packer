#!/usr/bin/env python3
'''
py1packer: pack files in a directory into a single self-extracting Python script, then optionally delete originals of the packed directory.
The self-extracting script unpacks files and leaves them by default.
Features:
  - overwrite policies: skip, increment
  - recursive packing
  - exclude patterns
  - dry-run mode
  - delete originals after packing
  - verbose/debug logging
'''

import argparse
import base64
import logging
import os
import sys
import shutil  # Import shutil for rmtree

from itertools import count


def find_output_path(base, policy):
    if not os.path.exists(base):
        return base
    if policy == 'skip':
        logging.error(f"output exists and policy=skip: {base}")
        sys.exit(1)
    if policy == 'increment':
        name, ext = os.path.splitext(base)
        for i in count(2):
            candidate = f"{name}_{i}{ext}"
            if not os.path.exists(candidate):
                return candidate
    logging.error(f"unknown overwrite policy: {policy}")
    sys.exit(1)


def gather_files(root_dir, exclude, recursive):
    patterns = set(exclude or [])
    collected_files = []
    collected_dirs = set()  # Keep track of directories
    # Walk topdown=True by default
    for dirpath, dirs, files in os.walk(root_dir, topdown=True):
        # Exclude directories based on patterns
        # Create a new list for dirs to allow modification during iteration
        dirs_to_process = []
        for d in dirs:
            rel_dir = os.path.relpath(os.path.join(dirpath, d), root_dir)
            # Check if the directory itself or any parent is explicitly excluded
            if any(rel_dir == p or rel_dir.startswith(p + os.sep) for p in patterns):
                logging.debug(f"excluded directory {rel_dir}")
            else:
                dirs_to_process.append(d)
                # Add the directory itself if it's not the root
                if rel_dir != '.':
                    collected_dirs.add(rel_dir)

        dirs[:] = dirs_to_process  # Update dirs in-place for os.walk

        for fname in files:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root_dir)
            # Check if the file or its parent directory is explicitly excluded
            if any(rel == p or rel.startswith(p + os.sep) or os.path.dirname(rel).startswith(p + os.sep) for p in patterns):
                logging.debug(f"excluded file {rel}")
                continue

            collected_files.append(rel)
            # Add parent directories of the file to collected_dirs
            parent_dir = os.path.dirname(rel)
            if parent_dir and parent_dir != '.':
                collected_dirs.add(parent_dir)

        if not recursive:
            # If not recursive, stop processing subdirectories
            dirs[:] = []

    # Sort directories by depth (parent before child) for reliable creation
    sorted_dirs = sorted(list(collected_dirs), key=lambda d: d.count(os.sep))

    return collected_files, sorted_dirs


def encode_files(files, root):
    result = {}
    for rel in files:
        path = os.path.join(root, rel)
        try:
            with open(path, 'rb') as f:
                result[rel] = base64.b64encode(f.read()).decode('ascii')
            logging.debug(f"encoded {rel}")
        except Exception as e:
            logging.warning(f"could not encode {rel}: {e}")
            # Optionally skip this file or exit
    return result


# Removed no_delete_extract parameter as extractor defaults to not deleting
def build_extractor(data_map, directories_to_create, output):
    lines = []
    lines.append('#!/usr/bin/env python3')
    lines.append('import os, base64, logging')
    lines.append(
        "logging.basicConfig(level=logging.INFO, format='%(message)s')")
    lines.append('')
    lines.append('def main():')

    # Create directories first, from parent to child
    if directories_to_create:  # Only add this section if there are directories to create
        lines.append('    logging.info("creating directories...")')
        for rel_dir in sorted(directories_to_create, key=lambda d: d.count(os.sep)):
            if rel_dir and rel_dir != '.':  # Don't try to create the current directory
                esc_dir = rel_dir.replace('\\', '\\\\').replace("'", "\\'")
                lines.append(f"    try:")
                lines.append(
                    f"        os.makedirs(r'{esc_dir}', exist_ok=True)")
                lines.append(
                    f"        logging.info('created directory {esc_dir}')")
                lines.append(f"    except Exception as e:")
                lines.append(
                    f"        logging.error(f'could not create directory {esc_dir}: {{e}}')")

    lines.append('    logging.info("extracting files...")')
    if not data_map:  # Add a message if no files were packed
        lines.append('    logging.info("no files to extract.")')
    else:
        for rel, b64 in data_map.items():
            esc = rel.replace('\\', '\\\\').replace("'", "\\'")
            lines.append(f"    try:")
            lines.append(
                f"        with open(r'{esc}','wb') as f: f.write(base64.b64decode('{b64}'))")
            lines.append(f"        logging.info('extracted {esc}')")
            lines.append(f"    except Exception as e:")
            lines.append(
                f"        logging.error(f'could not extract {esc}: {{e}}')")

    # Removed the cleanup logic (file and directory deletion) from the generated script

    lines.append('')
    lines.append("if __name__ == '__main__':")
    lines.append('    main()')
    content = '\n'.join(lines)

    try:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(content)
        logging.info(f"wrote extractor to {output}")
        try:
            os.chmod(output, 0o755)
        except Exception as e:
            logging.warning(
                f"could not set executable permission on {output}: {e}")
    except Exception as e:
        logging.error(f"could not write to output file {output}: {e}")
        sys.exit(1)


def delete_originals_packer(root, files_to_delete, dirs_to_delete):
    logging.info("cleaning up originals after packing...")
    # Delete files first
    for rel in files_to_delete:
        path = os.path.join(root, rel)
        try:
            os.remove(path)
            logging.info(f"deleted file {rel}")
        except FileNotFoundError:
            pass  # Already gone, no problem
        except Exception as e:
            logging.warning(f"could not delete file {rel}: {e}")

    # Delete empty directories bottom-up
    # Sort directories from child to parent for deletion
    for rel_dir in sorted(dirs_to_delete, key=lambda d: d.count(os.sep), reverse=True):
        path = os.path.join(root, rel_dir)
        # Don't try to remove the root directory itself
        if path == os.path.abspath(root):
            continue
        try:
            os.rmdir(path)
            logging.info(f"removed empty directory {rel_dir}")
        except OSError as e:
            # This is expected if the directory is not empty (e.g., due to an excluded file)
            logging.debug(f"could not remove directory {rel_dir}: {e}")
        except Exception as e:
            logging.warning(
                f"unexpected error removing directory {rel_dir}: {e}")


def parse_args():
    p = argparse.ArgumentParser(
        description='Pack a directory into a self-extracting script')
    p.add_argument('directory', help='dir to pack')
    p.add_argument('-o', '--output', default='packed.py', help='output script')
    p.add_argument('--overwrite', choices=['skip', 'increment'],
                   default='increment', help='overwrite policy')
    p.add_argument('-r', '--recursive', action='store_true',
                   help='include subdirs')
    # Use type=str for exclude to handle relative paths correctly
    p.add_argument('-e', '--exclude', nargs='*', type=str, default=[],
                   help='relative paths (files or directories) to exclude')
    # Removed --no-delete-extractor flag
    # Explicit flag for deletion after packing
    p.add_argument('--delete-packer', action='store_true',
                   help='delete originals after packing')
    p.add_argument('--dry-run', action='store_true',
                   help='show actions without writing or deleting')
    p.add_argument('-v', '--verbose', action='store_true', help='debug mode')
    return p.parse_args()


def main():
    args = parse_args()
    lvl = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=lvl, format='%(levelname)s: %(message)s')

    root = args.directory
    if not os.path.isdir(root):
        logging.error(f"not a directory: {root}")
        sys.exit(1)

    # Ensure exclude paths are relative to the root directory and normalized
    excludes = [os.path.normpath(os.path.relpath(p, root)) if os.path.isabs(
        p) else os.path.normpath(p) for p in args.exclude]
    # Always exclude the output file and the packer script itself if they are within the root
    try:
        packer_script_abs = os.path.abspath(__file__)
        root_abs = os.path.abspath(root)
        if packer_script_abs.startswith(root_abs + os.sep) or packer_script_abs == root_abs:
            packer_script_rel = os.path.relpath(packer_script_abs, root_abs)
            excludes.append(os.path.normpath(packer_script_rel))
    except ValueError:  # Handles cases where root and script are on different drives
        pass

    output_abs = os.path.abspath(args.output)
    root_abs = os.path.abspath(root)
    if output_abs.startswith(root_abs + os.sep) or output_abs == root_abs:
        output_rel = os.path.relpath(output_abs, root_abs)
        excludes.append(os.path.normpath(output_rel))

    # Remove duplicates from excludes
    excludes = list(set(excludes))
    logging.debug(f"final exclude patterns: {excludes}")

    files_to_pack, dirs_to_include_in_extractor = gather_files(
        root, excludes, args.recursive)
    logging.info(
        f"found {len(files_to_pack)} files and {len(dirs_to_include_in_extractor)} directories to include in the extractor")
    logging.debug(f"files to pack: {files_to_pack}")
    logging.debug(f"directories to include: {dirs_to_include_in_extractor}")

    enc = encode_files(files_to_pack, root)
    if args.dry_run:
        logging.info("dry-run: no files written or deleted")
        return

    # Pass the list of directories that need to be created by the extractor
    # Removed no_delete_extractor argument
    build_extractor(enc, dirs_to_include_in_extractor, args.output)
    logging.info(f"packed into {args.output}")

    # Delete originals in packer only if --delete-packer is specified
    if args.delete_packer:
        # We need to identify the files and directories that *were* processed for packing
        # This is slightly different from files_to_pack and dirs_to_include_in_extractor
        # because those lists are already filtered by excludes.
        # We need to get the list *before* excluding.
        # A simpler approach for deletion is to walk the original directory again,
        # and delete anything *not* in the exclude list and not the output file/packer script.

        logging.info("identifying originals for deletion...")
        originals_to_delete = []
        original_dirs_to_delete = set()
        # Walk bottom-up for deletion
        for dirpath, dirs, files in os.walk(root, topdown=False):
            for fname in files:
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, root)
                if os.path.normpath(rel_path) not in excludes:
                    originals_to_delete.append(os.path.normpath(rel_path))

            # Collect directories that might become empty
            rel_dir_path = os.path.relpath(dirpath, root)
            if os.path.normpath(rel_dir_path) != '.' and os.path.normpath(rel_dir_path) not in excludes:
                original_dirs_to_delete.add(os.path.normpath(rel_dir_path))

        delete_originals_packer(root, originals_to_delete,
                                list(original_dirs_to_delete))


if __name__ == '__main__':
    main()
