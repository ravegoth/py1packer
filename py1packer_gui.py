#!/usr/bin/env python3
import logging
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import py1packer


class QueueHandler(logging.Handler):
    def __init__(self, event_queue):
        super().__init__()
        self.event_queue = event_queue

    def emit(self, record):
        self.event_queue.put(("log", record.levelname, self.format(record)))


class PackerApp:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.worker = None
        self.default_output = os.path.join(os.getcwd(), "packed.py")
        self.colors = {
            "bg": "#0f172a",
            "panel": "#111827",
            "panel_alt": "#162033",
            "field": "#0b1220",
            "border": "#273449",
            "text": "#e5e7eb",
            "muted": "#94a3b8",
            "accent": "#38bdf8",
            "accent_dark": "#0ea5e9",
            "danger": "#f97316",
            "success": "#22c55e",
            "error": "#ef4444",
            "warning": "#f59e0b",
        }
        self.setup_variables()
        self.setup_window()
        self.setup_styles()
        self.build_gui()
        self.root.after(80, self.process_events)

    def setup_variables(self):
        self.source_dir_var = tk.StringVar()
        self.output_file_var = tk.StringVar(value=self.default_output)
        self.exclude_entry_var = tk.StringVar()
        self.recursive_var = tk.BooleanVar(value=True)
        self.delete_packer_var = tk.BooleanVar(value=False)
        self.overwrite_policy_var = tk.StringVar(value="increment")
        self.status_var = tk.StringVar(value="Ready")
        self.summary_var = tk.StringVar(value="Choose a source directory to begin.")

    def setup_window(self):
        self.root.title("Py1Packer")
        self.root.geometry("1060x720")
        self.root.minsize(860, 620)
        self.root.configure(bg=self.colors["bg"])

    def setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 10), borderwidth=0, focuscolor=self.colors["accent"])
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Panel.TFrame", background=self.colors["panel"], borderwidth=1, relief="solid")
        style.configure("Alt.TFrame", background=self.colors["panel_alt"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Panel.TLabel", background=self.colors["panel"], foreground=self.colors["text"])
        style.configure("Muted.TLabel", background=self.colors["panel"], foreground=self.colors["muted"])
        style.configure("Title.TLabel", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI Semibold", 22))
        style.configure("Subtitle.TLabel", background=self.colors["bg"], foreground=self.colors["muted"], font=("Segoe UI", 10))
        style.configure("Status.TLabel", background=self.colors["panel_alt"], foreground=self.colors["accent"], font=("Segoe UI Semibold", 10), padding=(14, 7))
        style.configure("TEntry", fieldbackground=self.colors["field"], foreground=self.colors["text"], insertcolor=self.colors["text"], bordercolor=self.colors["border"], lightcolor=self.colors["border"], darkcolor=self.colors["border"], padding=8)
        style.map("TEntry", bordercolor=[("focus", self.colors["accent"])])
        style.configure("TCombobox", fieldbackground=self.colors["field"], background=self.colors["field"], foreground=self.colors["text"], arrowcolor=self.colors["accent"], bordercolor=self.colors["border"], padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", self.colors["field"])], foreground=[("readonly", self.colors["text"])])
        style.configure("TButton", background=self.colors["panel_alt"], foreground=self.colors["text"], font=("Segoe UI Semibold", 10), padding=(12, 9), bordercolor=self.colors["border"])
        style.map("TButton", background=[("active", self.colors["border"]), ("disabled", self.colors["panel"])], foreground=[("disabled", self.colors["muted"])])
        style.configure("Accent.TButton", background=self.colors["accent_dark"], foreground="#ffffff", bordercolor=self.colors["accent_dark"])
        style.map("Accent.TButton", background=[("active", self.colors["accent"]), ("disabled", self.colors["panel"])])
        style.configure("Danger.TButton", background="#7c2d12", foreground="#fed7aa", bordercolor="#9a3412")
        style.map("Danger.TButton", background=[("active", "#9a3412")])
        style.configure("TCheckbutton", background=self.colors["panel"], foreground=self.colors["text"], font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", self.colors["panel"])], foreground=[("disabled", self.colors["muted"])])
        style.configure("Horizontal.TProgressbar", troughcolor=self.colors["field"], background=self.colors["accent"], bordercolor=self.colors["field"], lightcolor=self.colors["accent"], darkcolor=self.colors["accent"])

    def build_gui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=(22, 20, 22, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ttk.Label(header, text="Py1Packer", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Bundle a folder into one self-extracting Python script.", style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Label(header, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=1, rowspan=2, sticky="e")

        shell = ttk.Frame(self.root, padding=(22, 0, 22, 18))
        shell.grid(row=1, column=0, sticky="nsew")
        shell.grid_columnconfigure(0, minsize=390)
        shell.grid_columnconfigure(1, weight=1)
        shell.grid_rowconfigure(0, weight=1)

        left = ttk.Frame(shell, style="Panel.TFrame", padding=18)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.grid_columnconfigure(0, weight=1)

        right = ttk.Frame(shell, style="Panel.TFrame", padding=18)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(2, weight=1)

        self.build_configuration(left)
        self.build_log_panel(right)
        self.busy_widgets = [
            self.source_entry,
            self.output_entry,
            self.browse_source_button,
            self.browse_output_button,
            self.exclude_entry,
            self.add_exclude_button,
            self.add_file_button,
            self.add_folder_button,
            self.remove_exclude_button,
            self.clear_exclude_button,
            self.recursive_check,
            self.delete_check,
            self.overwrite_menu,
            self.dry_run_button,
            self.pack_button,
        ]

    def build_configuration(self, parent):
        ttk.Label(parent, text="Source", style="Panel.TLabel", font=("Segoe UI Semibold", 12)).grid(row=0, column=0, sticky="w")
        ttk.Label(parent, text="Pick the folder that will be embedded.", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))
        source_row = ttk.Frame(parent, style="Panel.TFrame")
        source_row.grid(row=2, column=0, sticky="ew")
        source_row.grid_columnconfigure(0, weight=1)
        self.source_entry = ttk.Entry(source_row, textvariable=self.source_dir_var)
        self.source_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.browse_source_button = ttk.Button(source_row, text="Browse", command=self.browse_source)
        self.browse_source_button.grid(row=0, column=1)

        ttk.Label(parent, text="Output", style="Panel.TLabel", font=("Segoe UI Semibold", 12)).grid(row=3, column=0, sticky="w", pady=(22, 0))
        ttk.Label(parent, text="Choose where the generated script will be written.", style="Muted.TLabel").grid(row=4, column=0, sticky="w", pady=(2, 10))
        output_row = ttk.Frame(parent, style="Panel.TFrame")
        output_row.grid(row=5, column=0, sticky="ew")
        output_row.grid_columnconfigure(0, weight=1)
        self.output_entry = ttk.Entry(output_row, textvariable=self.output_file_var)
        self.output_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.browse_output_button = ttk.Button(output_row, text="Save As", command=self.browse_output)
        self.browse_output_button.grid(row=0, column=1)

        options = ttk.Frame(parent, style="Alt.TFrame", padding=14)
        options.grid(row=6, column=0, sticky="ew", pady=(22, 0))
        options.grid_columnconfigure(1, weight=1)
        self.recursive_check = ttk.Checkbutton(options, text="Include subfolders", variable=self.recursive_var)
        self.recursive_check.grid(row=0, column=0, columnspan=2, sticky="w")
        self.delete_check = ttk.Checkbutton(options, text="Delete packed originals", variable=self.delete_packer_var)
        self.delete_check.grid(row=1, column=0, columnspan=2, sticky="w", pady=(9, 0))
        ttk.Label(options, text="Overwrite", style="Panel.TLabel").grid(row=2, column=0, sticky="w", pady=(14, 0))
        self.overwrite_menu = ttk.Combobox(options, textvariable=self.overwrite_policy_var, values=("increment", "skip"), state="readonly", width=14)
        self.overwrite_menu.grid(row=2, column=1, sticky="e", pady=(14, 0))

        ttk.Label(parent, text="Exclusions", style="Panel.TLabel", font=("Segoe UI Semibold", 12)).grid(row=7, column=0, sticky="w", pady=(22, 0))
        ttk.Label(parent, text="Relative paths that should not be packed.", style="Muted.TLabel").grid(row=8, column=0, sticky="w", pady=(2, 10))
        exclude_box = ttk.Frame(parent, style="Panel.TFrame")
        exclude_box.grid(row=9, column=0, sticky="nsew")
        exclude_box.grid_columnconfigure(0, weight=1)
        exclude_box.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(9, weight=1)
        self.exclude_listbox = tk.Listbox(exclude_box, height=8, selectmode=tk.EXTENDED, bg=self.colors["field"], fg=self.colors["text"], selectbackground=self.colors["accent_dark"], selectforeground="#ffffff", highlightthickness=1, highlightbackground=self.colors["border"], highlightcolor=self.colors["accent"], relief="flat", activestyle="none", font=("Segoe UI", 10))
        self.exclude_listbox.grid(row=0, column=0, sticky="nsew")
        exclude_scroll = ttk.Scrollbar(exclude_box, orient="vertical", command=self.exclude_listbox.yview)
        exclude_scroll.grid(row=0, column=1, sticky="ns")
        self.exclude_listbox.configure(yscrollcommand=exclude_scroll.set)
        self.exclude_entry = ttk.Entry(exclude_box, textvariable=self.exclude_entry_var)
        self.exclude_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.exclude_entry.bind("<Return>", self.add_exclusion)
        exclude_buttons = ttk.Frame(exclude_box, style="Panel.TFrame")
        exclude_buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        for column in range(5):
            exclude_buttons.grid_columnconfigure(column, weight=1)
        self.add_exclude_button = ttk.Button(exclude_buttons, text="Add", command=self.add_exclusion)
        self.add_exclude_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.add_file_button = ttk.Button(exclude_buttons, text="File", command=self.add_exclusion_file)
        self.add_file_button.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        self.add_folder_button = ttk.Button(exclude_buttons, text="Folder", command=self.add_exclusion_folder)
        self.add_folder_button.grid(row=0, column=2, sticky="ew", padx=(0, 6))
        self.remove_exclude_button = ttk.Button(exclude_buttons, text="Remove", command=self.remove_exclusion)
        self.remove_exclude_button.grid(row=0, column=3, sticky="ew", padx=(0, 6))
        self.clear_exclude_button = ttk.Button(exclude_buttons, text="Clear", command=self.clear_exclusions)
        self.clear_exclude_button.grid(row=0, column=4, sticky="ew")

        actions = ttk.Frame(parent, style="Panel.TFrame")
        actions.grid(row=10, column=0, sticky="ew", pady=(20, 0))
        actions.grid_columnconfigure(0, weight=1)
        actions.grid_columnconfigure(1, weight=1)
        self.dry_run_button = ttk.Button(actions, text="Dry Run", command=lambda: self.start_packing(True))
        self.dry_run_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.pack_button = ttk.Button(actions, text="Pack", style="Accent.TButton", command=lambda: self.start_packing(False))
        self.pack_button.grid(row=0, column=1, sticky="ew")

    def build_log_panel(self, parent):
        top = ttk.Frame(parent, style="Panel.TFrame")
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ttk.Label(top, text="Run Log", style="Panel.TLabel", font=("Segoe UI Semibold", 12)).grid(row=0, column=0, sticky="w")
        ttk.Button(top, text="Clear", command=self.clear_log).grid(row=0, column=1, sticky="e")
        ttk.Label(parent, textvariable=self.summary_var, style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 12))
        self.log_text = scrolledtext.ScrolledText(parent, state="disabled", wrap=tk.WORD, bg=self.colors["field"], fg=self.colors["text"], insertbackground=self.colors["text"], selectbackground=self.colors["accent_dark"], relief="flat", highlightthickness=1, highlightbackground=self.colors["border"], highlightcolor=self.colors["accent"], font=("Consolas", 10), padx=12, pady=12)
        self.log_text.grid(row=2, column=0, sticky="nsew")
        self.log_text.tag_configure("INFO", foreground=self.colors["text"])
        self.log_text.tag_configure("DEBUG", foreground=self.colors["muted"])
        self.log_text.tag_configure("WARNING", foreground=self.colors["warning"])
        self.log_text.tag_configure("ERROR", foreground=self.colors["error"])
        self.log_text.tag_configure("SUCCESS", foreground=self.colors["success"])
        bottom = ttk.Frame(parent, style="Panel.TFrame")
        bottom.grid(row=3, column=0, sticky="ew", pady=(14, 0))
        bottom.grid_columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(bottom, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        ttk.Label(bottom, text="Idle", textvariable=self.status_var, style="Muted.TLabel").grid(row=0, column=1, sticky="e")

    def browse_source(self):
        selected = filedialog.askdirectory(title="Select source directory")
        if selected:
            self.source_dir_var.set(selected)
            current_output = self.output_file_var.get().strip()
            if not current_output or current_output == self.default_output:
                source_name = Path(selected).name or "packed"
                self.output_file_var.set(str(Path(selected).parent / f"{source_name}_packed.py"))
            self.summary_var.set("Source folder selected.")

    def browse_output(self):
        selected = filedialog.asksaveasfilename(title="Save output script as", defaultextension=".py", filetypes=(("Python scripts", "*.py"), ("All files", "*.*")))
        if selected:
            self.output_file_var.set(selected)

    def add_exclusion(self, event=None):
        value = py1packer.normalize_archive_path(self.exclude_entry_var.get())
        if value != "." and value not in self.exclude_listbox.get(0, tk.END):
            self.exclude_listbox.insert(tk.END, value)
        self.exclude_entry_var.set("")

    def add_exclusion_file(self):
        root_dir = self.source_dir_var.get().strip()
        selected = filedialog.askopenfilename(title="Select file to exclude", initialdir=root_dir if os.path.isdir(root_dir) else os.getcwd())
        self.add_exclusion_path(selected)

    def add_exclusion_folder(self):
        root_dir = self.source_dir_var.get().strip()
        selected = filedialog.askdirectory(title="Select folder to exclude", initialdir=root_dir if os.path.isdir(root_dir) else os.getcwd())
        self.add_exclusion_path(selected)

    def add_exclusion_path(self, selected):
        if not selected:
            return
        root_dir = self.source_dir_var.get().strip()
        value = selected
        if root_dir and os.path.isdir(root_dir) and py1packer.path_is_inside(selected, root_dir):
            value = os.path.relpath(selected, root_dir)
        value = py1packer.normalize_archive_path(value)
        if value != "." and value not in self.exclude_listbox.get(0, tk.END):
            self.exclude_listbox.insert(tk.END, value)

    def remove_exclusion(self):
        for index in reversed(self.exclude_listbox.curselection()):
            self.exclude_listbox.delete(index)

    def clear_exclusions(self):
        self.exclude_listbox.delete(0, tk.END)

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def validate_job(self, dry_run):
        root_dir = self.source_dir_var.get().strip()
        output_file = self.output_file_var.get().strip()
        if not root_dir or not os.path.isdir(root_dir):
            messagebox.showerror("Invalid source", "Select an existing source directory.")
            return None
        if not dry_run and not output_file:
            messagebox.showerror("Invalid output", "Choose an output file.")
            return None
        if self.delete_packer_var.get() and not dry_run:
            confirmed = messagebox.askyesno("Delete originals", "This will delete packed original files after the extractor is written. Continue?")
            if not confirmed:
                return None
        return {
            "root": root_dir,
            "output": output_file or self.default_output,
            "overwrite": self.overwrite_policy_var.get(),
            "recursive": self.recursive_var.get(),
            "exclude": list(self.exclude_listbox.get(0, tk.END)),
            "delete_packer": self.delete_packer_var.get(),
            "dry_run": dry_run,
        }

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        for widget in self.busy_widgets:
            try:
                widget.configure(state=state)
            except tk.TclError:
                pass
        if not busy:
            self.overwrite_menu.configure(state="readonly")

    def start_packing(self, dry_run):
        if self.worker and self.worker.is_alive():
            return
        job = self.validate_job(dry_run)
        if not job:
            return
        self.clear_log()
        self.set_busy(True)
        self.status_var.set("Running")
        self.summary_var.set("Scanning files and preparing package...")
        self.progress.start(10)
        self.worker = threading.Thread(target=self.run_job, args=(job,), daemon=True)
        self.worker.start()

    def run_job(self, job):
        handler = QueueHandler(self.events)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))
        logger = logging.getLogger()
        previous_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logging.info("Starting %s", "dry run" if job["dry_run"] else "pack")
            logging.info("Source: %s", job["root"])
            logging.info("Output: %s", job["output"])
            logging.info("Recursive: %s", job["recursive"])
            logging.info("Overwrite policy: %s", job["overwrite"])
            if job["exclude"]:
                logging.info("Exclusions: %s", ", ".join(job["exclude"]))
            result = py1packer.pack_directory(job["root"], job["output"], overwrite=job["overwrite"], recursive=job["recursive"], exclude=job["exclude"], dry_run=job["dry_run"], delete_packer=job["delete_packer"])
            if job["dry_run"]:
                logging.info("")
                logging.info("Files that would be packed:")
                if result["files"]:
                    for rel in result["files"]:
                        logging.info("  %s", rel)
                else:
                    logging.info("  No files matched.")
                logging.info("")
                logging.info("Directories that would be created:")
                if result["directories"]:
                    for rel in result["directories"]:
                        logging.info("  %s", rel)
                else:
                    logging.info("  No directories matched.")
            self.events.put(("done", True, result))
        except py1packer.PackerError as exc:
            logging.error("%s", exc)
            self.events.put(("done", False, None))
        except SystemExit as exc:
            logging.error("Operation stopped unexpectedly: %s", exc)
            self.events.put(("done", False, None))
        except Exception:
            logging.exception("Unexpected failure")
            self.events.put(("done", False, None))
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous_level)

    def process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "log":
                    self.append_log(event[1], event[2])
                elif event[0] == "done":
                    self.finish_job(event[1], event[2])
        except queue.Empty:
            pass
        self.root.after(80, self.process_events)

    def append_log(self, level, message):
        tag = level if level in ("DEBUG", "INFO", "WARNING", "ERROR") else "INFO"
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)

    def finish_job(self, success, result):
        self.progress.stop()
        self.set_busy(False)
        if success:
            files = len(result["files"])
            directories = len(result["directories"])
            output = result.get("output")
            if output:
                self.status_var.set("Complete")
                self.summary_var.set(f"Packed {files} files and {directories} directories into {output}.")
                self.append_log("SUCCESS", f"SUCCESS  Packed {files} files into {output}")
            else:
                self.status_var.set("Dry run complete")
                self.summary_var.set(f"Dry run found {files} files and {directories} directories.")
                self.append_log("SUCCESS", f"SUCCESS  Dry run found {files} files")
        else:
            self.status_var.set("Failed")
            self.summary_var.set("The operation failed. Check the log for details.")


def main():
    root = tk.Tk()
    PackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
