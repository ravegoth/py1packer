#!/usr/bin/env python3
"""
Py1Packer GUI: A graphical interface for packing files into a self-extracting Python script.

This script provides a user-friendly GUI built with Tkinter to access the functionalities
of the py1packer tool. It allows users to select directories, set packing options,
and view real-time logs of the process.
"""

import argparse
import base64
import logging
import os
import sys
import shutil
import threading
import queue
from itertools import count

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

class PackerLogic:
    """
    Encapsulates the core file processing logic of py1packer.
    This class is designed to be called from the GUI thread.
    """

    def find_output_path(self, base, policy, logger):
        if not os.path.exists(base):
            return base
        if policy == 'skip':
            logger.error(f"Output exists and policy=skip: {base}")
            return None
        if policy == 'increment':
            name, ext = os.path.splitext(base)
            for i in count(2):
                candidate = f"{name}_{i}{ext}"
                if not os.path.exists(candidate):
                    return candidate
        logger.error(f"Unknown overwrite policy: {policy}")
        return None

    def gather_files(self, root_dir, exclude, recursive, logger):
        patterns = set(exclude or [])
        collected_files = []
        collected_dirs = set()
        for dirpath, dirs, files in os.walk(root_dir, topdown=True):
            dirs_to_process = []
            for d in dirs:
                rel_dir = os.path.relpath(os.path.join(dirpath, d), root_dir)
                if any(rel_dir == p or rel_dir.startswith(p + os.sep) for p in patterns):
                    logger.debug(f"Excluded directory {rel_dir}")
                else:
                    dirs_to_process.append(d)
                    if rel_dir != '.':
                        collected_dirs.add(rel_dir)
            dirs[:] = dirs_to_process
            for fname in files:
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, root_dir)
                if any(rel == p or rel.startswith(p + os.sep) or os.path.dirname(rel).startswith(p + os.sep) for p in patterns):
                    logger.debug(f"Excluded file {rel}")
                    continue
                collected_files.append(rel)
                parent_dir = os.path.dirname(rel)
                if parent_dir and parent_dir != '.':
                    collected_dirs.add(parent_dir)
            if not recursive:
                dirs[:] = []
        return collected_files, sorted(list(collected_dirs), key=lambda d: d.count(os.sep))

    def encode_files(self, files, root, logger):
        result = {}
        for rel in files:
            path = os.path.join(root, rel)
            try:
                with open(path, 'rb') as f:
                    result[rel] = base64.b64encode(f.read()).decode('ascii')
                logger.debug(f"Encoded {rel}")
            except Exception as e:
                logger.warning(f"Could not encode {rel}: {e}")
        return result

    def build_extractor(self, data_map, directories_to_create, output, logger):
        lines = [
            '#!/usr/bin/env python3',
            'import os, base64, logging, sys',
            "logging.basicConfig(level=logging.INFO, format='%(message)s', stream=sys.stdout)",
            '',
            'def main():',
        ]
        if directories_to_create:
            lines.append('    logging.info("Creating directories...")')
            for rel_dir in sorted(directories_to_create, key=lambda d: d.count(os.sep)):
                if rel_dir and rel_dir != '.':
                    esc_dir = rel_dir.replace('\\', '\\\\').replace("'", "\\'")
                    lines.extend([
                        f"    try:",
                        f"        os.makedirs(r'{esc_dir}', exist_ok=True)",
                        f"        logging.info(f'  Created directory: {esc_dir}')",
                        f"    except Exception as e:",
                        f"        logging.error(f'  Could not create directory {esc_dir}: {{e}}')",
                    ])
        lines.append('    logging.info("Extracting files...")')
        if not data_map:
            lines.append('    logging.info("  No files to extract.")')
        else:
            for rel, b64 in data_map.items():
                esc = rel.replace('\\', '\\\\').replace("'", "\\'")
                lines.extend([
                    f"    try:",
                    f"        with open(r'{esc}','wb') as f: f.write(base64.b64decode('{b64}'))",
                    f"        logging.info(f'  Extracted: {esc}')",
                    f"    except Exception as e:",
                    f"        logging.error(f'  Could not extract {esc}: {{e}}')",
                ])
        lines.append('    logging.info("Extraction complete.")')
        lines.extend(['', "if __name__ == '__main__':", '    main()'])
        content = '\n'.join(lines)
        try:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Wrote extractor to {output}")
            try:
                os.chmod(output, 0o755)
            except Exception as e:
                logger.warning(f"Could not set executable permission on {output}: {e}")
        except Exception as e:
            logger.error(f"Could not write to output file {output}: {e}")
            return False
        return True

    def delete_originals_packer(self, root, files_to_delete, dirs_to_delete, logger):
        logger.info("Cleaning up originals after packing...")
        for rel in files_to_delete:
            path = os.path.join(root, rel)
            try:
                os.remove(path)
                logger.info(f"Deleted file {rel}")
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Could not delete file {rel}: {e}")
        for rel_dir in sorted(dirs_to_delete, key=lambda d: d.count(os.sep), reverse=True):
            path = os.path.join(root, rel_dir)
            if path == os.path.abspath(root):
                continue
            try:
                os.rmdir(path)
                logger.info(f"Removed empty directory {rel_dir}")
            except OSError as e:
                logger.debug(f"Could not remove directory {rel_dir}: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error removing directory {rel_dir}: {e}")

class QueueHandler(logging.Handler):
    """
    A custom logging handler that directs logs to a queue.
    The GUI can then pull logs from the queue to display them.
    """
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))

class PackerApp:
    """
    The main class for the Py1Packer GUI.
    """
    def __init__(self, root):
        self.root = root
        self.packer_logic = PackerLogic()
        self.log_queue = queue.Queue()
        self.setup_logging()
        self.setup_gui()

    def setup_logging(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(QueueHandler(self.log_queue))

    def setup_gui(self):
        self.root.title("Py1Packer")
        self.root.geometry("800x650")
        self.root.minsize(600, 500)
        self.root.configure(bg="#2E2E2E")
        style = ttk.Style(self.root)
        style.theme_use('clam')
        BG_COLOR = "#2E2E2E"
        FG_COLOR = "#E0E0E0"
        INACTIVE_FG_COLOR = "#A0A0A0"
        ENTRY_BG_COLOR = "#3C3C3C"
        BUTTON_BG_COLOR = "#007ACC"
        BUTTON_FG_COLOR = "#FFFFFF"
        BUTTON_ACTIVE_BG = "#005F9E"
        FRAME_BG = "#252526"
        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, fieldbackground=ENTRY_BG_COLOR, borderwidth=0)
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 10))
        style.configure('TButton', background=BUTTON_BG_COLOR, foreground=BUTTON_FG_COLOR, font=('Segoe UI', 10, 'bold'), borderwidth=1, focusthickness=0)
        style.map('TButton', background=[('active', BUTTON_ACTIVE_BG)], relief=[('pressed', 'sunken')])
        style.configure('TCheckbutton', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 10))
        style.map('TCheckbutton', background=[('active', BG_COLOR)])
        style.configure('TLabelframe', background=BG_COLOR, bordercolor=INACTIVE_FG_COLOR)
        style.configure('TLabelframe.Label', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 11, 'bold'))
        style.configure('TEntry', fieldbackground=ENTRY_BG_COLOR, foreground=FG_COLOR, insertcolor=FG_COLOR, bordercolor=INACTIVE_FG_COLOR, borderwidth=1)
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)
        main_frame.grid_rowconfigure(4, weight=3)
        self.source_dir_var = tk.StringVar()
        self.output_file_var = tk.StringVar(value=os.path.join(os.getcwd(), "packed.py"))
        self.recursive_var = tk.BooleanVar(value=True)
        self.delete_packer_var = tk.BooleanVar(value=False)
        self.overwrite_policy_var = tk.StringVar(value="increment")
        self.exclude_entry_var = tk.StringVar()
        ttk.Label(main_frame, text="Source Directory:").grid(row=0, column=0, sticky="w", pady=(0, 5))
        source_entry = ttk.Entry(main_frame, textvariable=self.source_dir_var)
        source_entry.grid(row=0, column=1, sticky="ew", padx=(5, 5))
        ttk.Button(main_frame, text="Browse...", command=self.browse_source).grid(row=0, column=2, sticky="ew", padx=(5, 0))
        ttk.Label(main_frame, text="Output File:").grid(row=1, column=0, sticky="w", pady=(5, 10))
        output_entry = ttk.Entry(main_frame, textvariable=self.output_file_var)
        output_entry.grid(row=1, column=1, sticky="ew", padx=(5, 5))
        ttk.Button(main_frame, text="Save As...", command=self.browse_output).grid(row=1, column=2, sticky="ew", padx=(5, 0))
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
        options_frame.grid_columnconfigure(1, weight=1)
        ttk.Checkbutton(options_frame, text="Recursive", variable=self.recursive_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(options_frame, text="Delete Originals After Packing", variable=self.delete_packer_var).grid(row=0, column=1, sticky="w", padx=20)
        ttk.Label(options_frame, text="Overwrite Policy:").grid(row=0, column=2, sticky="w", padx=(20, 5))
        overwrite_menu = ttk.Combobox(options_frame, textvariable=self.overwrite_policy_var, values=["increment", "skip"], state="readonly", width=12)
        overwrite_menu.grid(row=0, column=3, sticky="w")
        exclude_frame = ttk.LabelFrame(main_frame, text="Exclude Relative Paths (Files or Directories)", padding="10")
        exclude_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=10)
        exclude_frame.grid_columnconfigure(0, weight=1)
        exclude_frame.grid_rowconfigure(0, weight=1)
        self.exclude_listbox = tk.Listbox(exclude_frame, bg=ENTRY_BG_COLOR, fg=FG_COLOR, selectbackground=BUTTON_BG_COLOR, activestyle='none', borderwidth=1, relief="solid")
        self.exclude_listbox.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 5))
        exclude_entry = ttk.Entry(exclude_frame, textvariable=self.exclude_entry_var)
        exclude_entry.grid(row=1, column=0, sticky="ew", pady=(5, 0), padx=(0, 5))
        exclude_entry.bind("<Return>", self.add_exclusion)
        add_remove_frame = ttk.Frame(exclude_frame)
        add_remove_frame.grid(row=1, column=1, sticky="ew")
        ttk.Button(add_remove_frame, text="Add", command=self.add_exclusion).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        ttk.Button(add_remove_frame, text="Remove Selected", command=self.remove_exclusion).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=10)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_frame, state='disabled', bg=ENTRY_BG_COLOR, fg=INACTIVE_FG_COLOR, font=('Consolas', 9), wrap=tk.WORD, borderwidth=1, relief="solid")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)
        action_frame.grid_columnconfigure(1, weight=1)
        self.dry_run_button = ttk.Button(action_frame, text="Dry Run", command=lambda: self.start_packing(dry_run=True))
        self.dry_run_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.pack_button = ttk.Button(action_frame, text="Pack", command=lambda: self.start_packing(dry_run=False))
        self.pack_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        self.root.after(100, self.process_log_queue)

    def browse_source(self):
        directory = filedialog.askdirectory(title="Select Source Directory")
        if directory:
            self.source_dir_var.set(directory)

    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Output Script As",
            defaultextension=".py",
            filetypes=[("Python Scripts", "*.py"), ("All Files", "*.*")]
        )
        if filename:
            self.output_file_var.set(filename)

    def add_exclusion(self, event=None):
        path = self.exclude_entry_var.get().strip()
        if path and path not in self.exclude_listbox.get(0, tk.END):
            self.exclude_listbox.insert(tk.END, path)
            self.exclude_entry_var.set("")

    def remove_exclusion(self):
        selected_indices = self.exclude_listbox.curselection()
        for i in reversed(selected_indices):
            self.exclude_listbox.delete(i)

    def process_log_queue(self):
        try:
            while True:
                record = self.log_queue.get_nowait()
                self.log_text.configure(state='normal')
                self.log_text.insert(tk.END, record + '\n')
                self.log_text.configure(state='disabled')
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_log_queue)
    
    def set_ui_state(self, enabled):
        state = 'normal' if enabled else 'disabled'
        self.pack_button.config(state=state)
        self.dry_run_button.config(state=state)

    def start_packing(self, dry_run=False):
        source_dir = self.source_dir_var.get()
        if not source_dir or not os.path.isdir(source_dir):
            messagebox.showerror("Error", "Please select a valid source directory.")
            return
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        self.set_ui_state(False)
        thread = threading.Thread(target=self._run_packing_thread, args=(dry_run,), daemon=True)
        thread.start()

    def _run_packing_thread(self, dry_run):
        try:
            root_dir = self.source_dir_var.get()
            output_file = self.output_file_var.get()
            overwrite_policy = self.overwrite_policy_var.get()
            is_recursive = self.recursive_var.get()
            do_delete_packer = self.delete_packer_var.get()
            excludes = list(self.exclude_listbox.get(0, tk.END))
            self.logger.info("="*50)
            self.logger.info(f"Starting {'DRY RUN' if dry_run else 'PACK'} operation...")
            self.logger.info(f"Source: {root_dir}")
            self.logger.info(f"Output: {output_file}")
            self.logger.info(f"Recursive: {is_recursive}, Delete Originals: {do_delete_packer}")
            try:
                if os.path.abspath(output_file).startswith(os.path.abspath(root_dir)):
                    output_rel = os.path.relpath(output_file, root_dir)
                    if output_rel not in excludes:
                        excludes.append(os.path.normpath(output_rel))
                        self.logger.info(f"Auto-excluding output file: {output_rel}")
            except (ValueError, TypeError): pass
            self.logger.info(f"Final exclude patterns: {excludes if excludes else 'None'}")
            files_to_pack, dirs_to_create = self.packer_logic.gather_files(root_dir, excludes, is_recursive, self.logger)
            self.logger.info(f"Found {len(files_to_pack)} files and {len(dirs_to_create)} directories to include.")
            if dry_run:
                self.logger.info("\n--- Files to be packed ---")
                for f in files_to_pack: self.logger.info(f"  - {f}")
                self.logger.info("\n--- Directories to be created in extractor ---")
                for d in dirs_to_create: self.logger.info(f"  - {d}")
                self.logger.info("\nDRY RUN COMPLETE: No files were written or deleted.")
                return
            final_output_path = self.packer_logic.find_output_path(output_file, overwrite_policy, self.logger)
            if not final_output_path:
                self.logger.error("Packing failed: Could not determine output path.")
                return
            encoded_data = self.packer_logic.encode_files(files_to_pack, root_dir, self.logger)
            success = self.packer_logic.build_extractor(encoded_data, dirs_to_create, final_output_path, self.logger)
            if not success:
                 self.logger.error("Packing failed: Could not build extractor script.")
                 return
            self.logger.info(f"Successfully packed into {final_output_path}")
            if do_delete_packer:
                self.packer_logic.delete_originals_packer(root_dir, files_to_pack, dirs_to_create, self.logger)
            self.logger.info("Operation finished successfully.")
        except Exception as e:
            self.logger.error(f"\nAn unexpected error occurred: {e}", exc_info=True)
        finally:
            self.set_ui_state(True)

if __name__ == '__main__':
    root = tk.Tk()
    app = PackerApp(root)
    root.mainloop()
