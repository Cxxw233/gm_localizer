import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import re
import struct
import binascii
import hashlib
from collections import defaultdict
import threading
import time
import sys
import json
# 使用 Python 标准库

class GamemakerLocalizer:
    def __init__(self, root):
        self.root = root
        self.root.title("GameMaker YYC 本地化工具 Debug")
        self.root.geometry("1980x1080")
        self.root.configure(bg="#1e293b")
        
        self.file_path = ""
        self.original_data = bytearray()
        self.modified_data = bytearray()
        self.strings = []
        self.backup_created = False
        self.processing = False
        self.running = True
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.bg_color = "#1e293b"
        self.card_bg = "#334155"
        self.text_bg = "#475569"
        self.accent_color = "#0ea5e9"
        self.success_color = "#10b981"
        self.warning_color = "#f59e0b"
        self.error_color = "#ef4444"
        self.text_color = "#e2e8f0"
        self.subtle_text = "#94a3b8"
        
        self.style.configure('.', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TLabelframe', background=self.card_bg, foreground=self.text_color, 
                            bordercolor="#475569", borderwidth=2)
        self.style.configure('TLabelframe.Label', background=self.card_bg, foreground=self.accent_color)
        self.style.configure('TButton', background="#475569", foreground=self.text_color, 
                            borderwidth=1, focusthickness=3, focuscolor=self.accent_color)
        self.style.map('TButton', 
                      background=[('active', '#64748b')],
                      foreground=[('active', 'white')])
        self.style.configure('TEntry', fieldbackground=self.text_bg, foreground="white", 
                            bordercolor="#475569", insertcolor="white")
        self.style.configure('TProgressbar', background=self.accent_color, troughcolor="#334155")
        
        self.style.configure('Treeview', background=self.text_bg, foreground=self.text_color, 
                            fieldbackground=self.text_bg, rowheight=25, borderwidth=0)
        self.style.map('Treeview', background=[('selected', self.accent_color)])
        self.style.configure('Treeview.Heading', background="#334155", foreground=self.text_color, 
                            relief='flat', font=('Segoe UI', 9, 'bold'))
        self.style.map('Treeview.Heading', background=[('active', '#475569')])
        
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', background="#334155", foreground=self.subtle_text, 
                            padding=[15, 5], borderwidth=0, font=('Segoe UI', 9, 'bold'))
        self.style.map('TNotebook.Tab', 
                      background=[('selected', self.card_bg), ('active', '#475569')],
                      foreground=[('selected', self.accent_color), ('active', 'white')])
        
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        for tag, config in {
            "header": {"font": ('Segoe UI', 12, 'bold'), "foreground": self.accent_color},
            "address": {"font": ('Consolas', 10), "foreground": self.warning_color},
            "warning": {"foreground": self.error_color, "font": ('Segoe UI', 10, 'bold')}
        }.items():
            self.preview_text.tag_configure(tag, **config)
            self.hex_text.tag_configure(tag, **config)

        self.show_startup_message()
        
    def on_close(self):
        self.running = False
        self.root.destroy()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="GameMaker YYC 本地化工具 开发版（BUG版）", 
                              font=('Segoe UI', 16, 'bold'), foreground=self.accent_color)
        title_label.pack(side=tk.LEFT)
        
        file_frame = ttk.LabelFrame(main_frame, text="文件操作")
        file_frame.pack(fill=tk.X, padx=5, pady=5, ipadx=10, ipady=10)
        
        file_row = ttk.Frame(file_frame)
        file_row.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(file_row, text="游戏文件:").pack(side=tk.LEFT, padx=(0, 5))
        self.file_entry = ttk.Entry(file_row, width=70)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        btn_container = ttk.Frame(file_row)
        btn_container.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.browse_btn = ttk.Button(btn_container, text="浏览...", command=self.browse_file)
        self.browse_btn.pack(side=tk.LEFT, padx=2)
        
        self.load_btn = ttk.Button(btn_container, text="加载文件", command=self.load_file, 
                                  style="Accent.TButton")
        self.load_btn.pack(side=tk.LEFT, padx=2)
        
        progress_frame = ttk.Frame(file_frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                      mode='determinate', length=300)
        self.progress.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="就绪", font=('Segoe UI', 9), 
                                      foreground=self.subtle_text)
        self.progress_label.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        list_frame = ttk.Frame(notebook, padding=10)
        notebook.add(list_frame, text="字符串列表")
        
        action_bar = ttk.Frame(list_frame)
        action_bar.pack(fill=tk.X, pady=(0, 10))
        
        search_frame = ttk.Frame(action_bar)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_strings)
        
        action_btn_frame = ttk.Frame(action_bar)
        action_btn_frame.pack(side=tk.RIGHT)
        
        self.export_btn = ttk.Button(action_btn_frame, text="导出JSON", command=self.export_json)
        self.export_btn.pack(side=tk.LEFT, padx=3)
        
        self.import_btn = ttk.Button(action_btn_frame, text="导入JSON", command=self.import_json)
        self.import_btn.pack(side=tk.LEFT, padx=3)
        
        columns = ("address", "original", "translation", "status", "length")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
        
        self.tree.heading("address", text="地址", anchor=tk.CENTER)
        self.tree.heading("original", text="原始文本", anchor=tk.W)
        self.tree.heading("translation", text="翻译文本", anchor=tk.W)
        self.tree.heading("status", text="状态", anchor=tk.CENTER)
        self.tree.heading("length", text="长度", anchor=tk.CENTER)
        
        self.tree.column("address", width=100, anchor=tk.CENTER)
        self.tree.column("original", width=300, anchor=tk.W)
        self.tree.column("translation", width=300, anchor=tk.W)
        self.tree.column("status", width=80, anchor=tk.CENTER)
        self.tree.column("length", width=60, anchor=tk.CENTER)
        
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_string_select)
        
        trans_frame = ttk.Frame(notebook, padding=10)
        notebook.add(trans_frame, text="翻译编辑器")
        
        orig_frame = ttk.LabelFrame(trans_frame, text="原始文本")
        orig_frame.pack(fill=tk.X, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.original_text = scrolledtext.ScrolledText(
            orig_frame, height=5, wrap=tk.WORD, bg=self.text_bg, fg="white", 
            font=('Segoe UI', 10), insertbackground='white', state='disabled'
        )
        self.original_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        trans_text_frame = ttk.LabelFrame(trans_frame, text="翻译文本")
        trans_text_frame.pack(fill=tk.X, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.translation_text = scrolledtext.ScrolledText(
            trans_text_frame, height=5, wrap=tk.WORD, bg=self.text_bg, fg="white", 
            font=('Segoe UI', 10), insertbackground='white'
        )
        self.translation_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.translation_text.bind('<KeyRelease>', self.on_translation_change)
        
        hex_frame = ttk.LabelFrame(trans_frame, text="十六进制预览")
        hex_frame.pack(fill=tk.X, padx=5, pady=5, ipadx=5, ipady=5)
        
        self.hex_text = tk.Text(
            hex_frame, height=5, wrap=tk.NONE, bg=self.text_bg, fg=self.warning_color, 
            font=('Consolas', 9), state='disabled', insertbackground='white'
        )
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        info_frame = ttk.Frame(trans_frame)
        info_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.length_var = tk.StringVar(value="原始长度: 0 字节 | 翻译长度: 0 字节")
        length_label = ttk.Label(info_frame, textvariable=self.length_var, font=('Segoe UI', 9),
                               foreground=self.subtle_text)
        length_label.pack(side=tk.LEFT, padx=(0, 10))
        
        btn_frame = ttk.Frame(info_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        self.clear_btn = ttk.Button(btn_frame, text="清除", command=self.clear_translation)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)
        
        self.apply_btn = ttk.Button(btn_frame, text="应用翻译", command=self.apply_translation,
                                  style="Accent.TButton")
        self.apply_btn.pack(side=tk.RIGHT, padx=5)
        
        preview_frame = ttk.Frame(notebook, padding=10)
        notebook.add(preview_frame, text="修改预览")
        
        self.preview_text = scrolledtext.ScrolledText(
            preview_frame, wrap=tk.WORD, bg=self.text_bg, fg="white", 
            font=('Consolas', 10), state='disabled', insertbackground='white'
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        stats_frame = ttk.Frame(bottom_frame)
        stats_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.stats_var = tk.StringVar(value="就绪 | 字符串: 0 | 已修改: 0")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_var, font=('Segoe UI', 9),
                              foreground=self.subtle_text)
        stats_label.pack(anchor=tk.W)
        
        action_frame = ttk.Frame(bottom_frame)
        action_frame.pack(side=tk.RIGHT)
        
        self.preview_btn = ttk.Button(action_frame, text="生成预览", command=self.generate_preview)
        self.preview_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(action_frame, text="保存修改", command=self.save_file,
                                 style="Success.TButton")
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        status_frame = ttk.Frame(self.root, height=25)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(
            status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W,
            font=('Segoe UI', 9), foreground=self.subtle_text,
            background="#0f172a", padding=(10, 0)
        )
        status_bar.pack(fill=tk.X)
        
        self.style.configure("Accent.TButton", background=self.accent_color, 
                           foreground="white", font=('Segoe UI', 10, 'bold'))
        self.style.map("Accent.TButton", 
                      background=[('active', '#0284c7')],
                      foreground=[('active', 'white')])
                      
        self.style.configure("Success.TButton", background=self.success_color, 
                           foreground="white", font=('Segoe UI', 10, 'bold'))
        self.style.map("Success.TButton", 
                      background=[('active', '#059669')],
                      foreground=[('active', 'white')])
        
        self.translation_text.focus()
        self.stats_var.set("就绪 | 字符串: 0 | 已修改: 0")

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="选择 Gamemaker YYC 游戏文件",
            filetypes=[("可执行文件", "*.exe"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
    
    def load_file(self):
        self.file_path = self.file_entry.get()
        if not self.file_path:
            messagebox.showerror("错误", "请选择游戏文件")
            return
            
        if not os.path.exists(self.file_path):
            messagebox.showerror("错误", "文件不存在")
            return
            
        try:
            if not self.backup_created:
                backup_path = self.file_path + ".bak"
                if not os.path.exists(backup_path):
                    import shutil
                    shutil.copy2(self.file_path, backup_path)
                    self.backup_created = True
                    self.status_var.set(f"已创建备份文件: {os.path.basename(backup_path)}")
            
            self.processing = True
            self.progress_var.set(0)
            self.progress_label.config(text="加载文件中...")
            
            self.set_ui_state(False)
            
            threading.Thread(target=self.load_and_scan_file, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("错误", f"加载文件失败: {str(e)}")
            self.processing = False
            self.set_ui_state(True)
    
    def set_ui_state(self, enabled):
        state = "normal" if enabled else "disabled"
        
        self.file_entry.config(state=state)
        self.search_entry.config(state=state)
        self.translation_text.config(state=state)
        
        if enabled:
            self.tree.bind("<<TreeviewSelect>>", self.on_string_select)
        else:
            self.tree.unbind("<<TreeviewSelect>>")
        
        for btn in [self.browse_btn, self.load_btn, self.apply_btn, 
                    self.clear_btn, self.save_btn, self.preview_btn,
                    self.export_btn, self.import_btn]:
            btn.config(state=state)
    
    def load_and_scan_file(self):
        try:
            with open(self.file_path, "rb") as f:
                self.original_data = bytearray(f.read())
            
            self.modified_data = bytearray(self.original_data)
            
            self.update_progress(10, "扫描字符串...")
            
            self.find_strings()
            
            if not self.running or not self.root.winfo_exists():
                return
                
            self.root.after(0, self.populate_string_list)
            
            self.update_progress(100, "文件加载完成")
            self.status_var.set(f"已加载文件: {os.path.basename(self.file_path)}")
            self.stats_var.set(f"就绪 | 字符串: {len(self.strings)} | 已修改: 0")
            
        except Exception as e:
            error_msg = str(e)
            if self.running and self.root.winfo_exists():
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("错误", f"加载文件失败: {msg}"))
        finally:
            self.processing = False
            if self.running and self.root.winfo_exists():
                self.root.after(0, lambda: self.set_ui_state(True))
    
    def update_progress(self, value, message):
        if not self.running or not self.root.winfo_exists():
            return
            
        self.progress_var.set(value)
        self.progress_label.config(text=message)
        self.root.update_idletasks()
    
    def find_strings(self): 
    # 经过多次修改，现在大部分牛鬼蛇神都会被搜到了。
        self.strings = []
        data = self.original_data
        
        pattern = re.compile(b'[\x09\x0A\x0D\x20-\x7E\xC0-\xFF][\x80-\xBF]*')
        
        pos = 0
        total = len(data)
        found = 0
        min_length = 2
        
        while pos < total and self.running:
            start = pos
            seq_length = 0
            char_count = 0
            
            while pos < total:
                match = pattern.match(data, pos)
                if match:
                    matched_len = match.end() - match.start()
                    pos += matched_len
                    seq_length += matched_len
                    char_count += 1
                else:
                    break
            
            if char_count >= min_length:
                end = start + seq_length
                try:
                    text = data[start:end].decode('utf-8')
                    self.strings.append({
                        'address': start,
                        'original': text,
                        'translation': "",
                        'status': "未修改",
                        'orig_length': seq_length
                    })
                    found += 1
                    
                    if found % 100 == 0:
                        self.update_progress(10 + (pos/total)*80, 
                                        f"已找到 {found} 个字符串...")
                except UnicodeDecodeError:
                    pass
            
            pos += 1
        
        self.strings.sort(key=lambda x: x['address'])
        self.update_progress(90, f"找到 {len(self.strings)} 个字符串，正在处理...")
    
    def populate_string_list(self):
        if not self.running or not self.root.winfo_exists():
            return

        self.filtered_strings = self.strings.copy()
        self.filter_strings()
            
    def filter_strings(self, event=None):
        search_term = self.search_var.get().strip().lower()

        if not hasattr(self, "strings") or not self.strings:
            return

        if not search_term:
            self.filtered_strings = self.strings.copy()
            self.status_var.set(f"显示全部 {len(self.filtered_strings)} 个字符串")
        else:
            self.filtered_strings = [
                s for s in self.strings
                if search_term in s['original'].lower() or search_term in s['translation'].lower()
            ]
            if self.filtered_strings:
                self.status_var.set(f"找到 {len(self.filtered_strings)} 个匹配项")
            else:
                self.status_var.set(f"没有找到匹配 '{search_term}' 的字符串")

        self.populate_tree_from_list(self.filtered_strings)

    def populate_tree_from_list(self, string_list):
        if not self.running or not self.root.winfo_exists():
            return

        self.tree.delete(*self.tree.get_children())

        modified_count = sum(1 for s in self.strings if s['status'] == "已修改")
        self.stats_var.set(f"就绪 | 字符串: {len(self.strings)} | 已修改: {modified_count}")

        for i, s in enumerate(string_list):
            display_original = s['original'].replace('\n', '\\n').replace('\r', '\\r')[:150] + ("..." if len(s['original']) > 150 else "")
            display_translation = s['translation'].replace('\n', '\\n').replace('\r', '\\r')[:150] + ("..." if len(s['translation']) > 150 else "")
            
            status_color = "#10b981" if s['status'] == "已修改" else "#94a3b8"
            
            self.tree.insert("", "end", values=(
                f"0x{s['address']:08X}",
                display_original,
                display_translation,
                s['status'],
                s['orig_length']
            ), tags=(s['status'],))
            
            self.tree.tag_configure("已修改", foreground=status_color)
            self.tree.tag_configure("未修改", foreground=self.subtle_text)

            if i % 100 == 0:
                self.root.update()

    def on_translation_change(self, event=None):
        if hasattr(self, 'current_item'):
            original = self.original_text.get(1.0, tk.END).strip()
            translation = self.translation_text.get(1.0, tk.END).strip()
            self.update_hex_preview(original, translation, self.current_orig_length)

    def on_string_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = selected[0]
        values = self.tree.item(item, "values")
        if not values:
            return
            
        address = values[0]
        addr_int = int(address.replace("0x", ""), 16)
        orig_length = int(values[4])
        
        original_bytes = self.original_data[addr_int:addr_int+orig_length]
        
        try:
            original = original_bytes.decode('utf-8')
            escaped_original = original.encode('unicode_escape').decode('utf-8')
        except UnicodeDecodeError:
            original = original_bytes.decode('utf-8', errors='ignore')
            escaped_original = original.encode('unicode_escape').decode('utf-8')
        
        escaped_translation = values[2]
        
        self.original_text.config(state='normal')
        self.original_text.delete(1.0, tk.END)
        self.original_text.insert(tk.END, escaped_original)
        self.original_text.config(state='disabled')
        
        self.translation_text.delete(1.0, tk.END)
        self.translation_text.insert(tk.END, escaped_translation)
        
        actual_original = escaped_original.encode('utf-8').decode('unicode_escape')
        actual_translation = escaped_translation.encode('utf-8').decode('unicode_escape')
        
        self.update_hex_preview(actual_original, actual_translation, orig_length)
        
        self.current_item = item
        self.current_address = address
        self.current_orig_length = orig_length
        self.current_escaped_original = escaped_original
        self.current_escaped_translation = escaped_translation
        
    def apply_translation(self):
        if not hasattr(self, 'current_item'):
            messagebox.showwarning("警告", "请先选择一个字符串")
            return
          
        translation = self.translation_text.get(1.0, tk.END).strip()
        if not translation:
            messagebox.showwarning("警告", "请输入翻译文本")
            return
            
        values = self.tree.item(self.current_item, "values")
        address = values[0]
        index = int(address.replace("0x", ""), 16)
        length = int(values[4])
        original = self.original_data[index:index+length].decode('utf-8', errors='ignore')
        
        trans_bytes = translation.encode('utf-8')
        if len(trans_bytes) > self.current_orig_length:
            if not messagebox.askyesno("长度超出", 
                                      "翻译文本超过可用空间，可能会破坏游戏。\n是否继续？"):
                return
        
        self.tree.set(self.current_item, "translation", translation)
        self.tree.set(self.current_item, "status", "已修改")
        
        addr_int = int(address.replace("0x", ""), 16)
        for s in self.strings:
            if s['address'] == addr_int:
                s['translation'] = translation
                s['status'] = "已修改"
                break
        
        self.update_hex_preview(original, translation, self.current_orig_length)
        
        self.status_var.set(f"已应用翻译: {original} -> {translation}")
        
        modified_count = sum(1 for s in self.strings if s['status'] == "已修改")
        self.stats_var.set(f"已应用翻译 | 字符串: {len(self.strings)} | 已修改: {modified_count}")
    
    def clear_translation(self):
        self.translation_text.delete(1.0, tk.END)
    
        if hasattr(self, 'current_item'):
            values = self.tree.item(self.current_item, "values")
            original = values[1]
            self.update_hex_preview(original, "", self.current_orig_length)
            
            if values[3] == "已修改":
                self.tree.set(self.current_item, "translation", "")
                self.tree.set(self.current_item, "status", "未修改")
                
                addr_int = int(self.current_address.replace("0x", ""), 16)
                for s in self.strings:
                    if s['address'] == addr_int:
                        s['translation'] = ""
                        s['status'] = "未修改"
                        break
                
                modified_count = sum(1 for s in self.strings if s['status'] == "已修改")
                self.stats_var.set(f"已清除翻译 | 字符串: {len(self.strings)} | 已修改: {modified_count}")
    
    def update_hex_preview(self, original, translation, orig_length):
        self.hex_text.config(state='normal')
        self.hex_text.delete(1.0, tk.END)
        
        try:
            orig_hex = binascii.hexlify(original.encode('utf-8')).decode('utf-8')
            orig_formatted = ' '.join(orig_hex[i:i+2].upper() for i in range(0, len(orig_hex), 2))
            
            trans_hex = binascii.hexlify(translation.encode('utf-8')).decode('utf-8') if translation else ""
            trans_formatted = ' '.join(trans_hex[i:i+2].upper() for i in range(0, len(trans_hex), 2)) if translation else ""
            
            self.hex_text.insert(tk.END, "原始: ", "header")
            self.hex_text.insert(tk.END, f"{orig_formatted}\n")
            
            if translation:
                self.hex_text.insert(tk.END, "翻译: ", "header")
                self.hex_text.insert(tk.END, f"{trans_formatted}\n")
            
            orig_len = len(original.encode('utf-8'))
            trans_len = len(translation.encode('utf-8')) if translation else 0
            self.length_var.set(f"原始长度: {orig_len} 字节 | 翻译长度: {trans_len} 字节")
            
            if translation and trans_len > orig_length:
                self.hex_text.insert(tk.END, "\n警告: 翻译文本超出可用空间!\n", "warning")
        except Exception as e:
            self.hex_text.insert(tk.END, f"十六进制预览错误: {str(e)}", "warning")
        
        self.hex_text.config(state='disabled')

    def generate_preview(self):
        modified_count = sum(1 for s in self.strings if s['status'] == "已修改")
        if modified_count == 0:
            messagebox.showinfo("预览", "没有修改需要预览")
            return
        
        self.preview_text.config(state='normal')
        self.preview_text.delete(1.0, tk.END)
        
        self.preview_text.insert(tk.END, "GameMaker YYC 本地化修改预览报告\n\n", "header")
        self.preview_text.insert(tk.END, f"文件: {os.path.basename(self.file_path)}\n")
        self.preview_text.insert(tk.END, f"修改时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.preview_text.insert(tk.END, f"修改数量: {modified_count}\n\n")
        self.preview_text.insert(tk.END, "="*80 + "\n\n")
        
        for s in self.strings:
            if s['status'] == "已修改":
                self.preview_text.insert(tk.END, f"地址: 0x{s['address']:08X}\n", "address")
                self.preview_text.insert(tk.END, f"原始: {s['original']}\n")
                self.preview_text.insert(tk.END, f"翻译: {s['translation']}\n")
                
                try:
                    orig_hex = binascii.hexlify(s['original'].encode('utf-8')).decode('utf-8')
                    orig_formatted = ' '.join(orig_hex[i:i+2].upper() for i in range(0, len(orig_hex), 2))
                    
                    trans_hex = binascii.hexlify(s['translation'].encode('utf-8')).decode('utf-8')
                    trans_formatted = ' '.join(trans_hex[i:i+2].upper() for i in range(0, len(trans_hex), 2))
                    
                    self.preview_text.insert(tk.END, f"原始十六进制: {orig_formatted}\n")
                    self.preview_text.insert(tk.END, f"修改十六进制: {trans_formatted}\n")
                except Exception as e:
                    self.preview_text.insert(tk.END, f"十六进制转换错误: {str(e)}\n")
                
                self.preview_text.insert(tk.END, "-"*80 + "\n")
        
        self.preview_text.config(state='disabled')
        self.status_var.set(f"已生成预览报告，包含 {modified_count} 个修改")
    
    def save_file(self):
        if not hasattr(self, 'modified_data') or not self.file_path:
            messagebox.showwarning("警告", "请先加载文件")
            return
            
        modified_count = 0
        for s in self.strings:
            if s['status'] == "已修改" and s['translation']:
                try:
                    trans_bytes = s['translation'].encode('utf-8')
                    
                    addr = s['address']
                    
                    trans_bytes = trans_bytes[:s['orig_length']]
                    
                    self.modified_data[addr:addr+len(trans_bytes)] = trans_bytes
                    
                    if len(trans_bytes) < s['orig_length']:
                        for i in range(addr + len(trans_bytes), addr + s['orig_length']):
                            self.modified_data[i] = 0
                    
                    modified_count += 1
                except Exception as e:
                    messagebox.showerror("错误", f"修改地址 0x{addr:08X} 时出错: {str(e)}")
                    return
        
        if modified_count == 0:
            messagebox.showinfo("保存", "没有修改需要保存")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="保存修改后的文件",
            defaultextension=".exe",
            initialfile=os.path.basename(self.file_path),
            filetypes=[("可执行文件", "*.exe"), ("所有文件", "*.*")]
        )
        
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(self.modified_data)
                
                orig_hash = hashlib.sha256(self.original_data).hexdigest()[:16]
                mod_hash = hashlib.sha256(self.modified_data).hexdigest()[:16]
                
                message = (
                    f"文件已成功保存到:\n{save_path}\n\n"
                    f"原始文件 SHA256: {orig_hash}...\n"
                    f"修改文件 SHA256: {mod_hash}...\n\n"
                    f"共修改了 {modified_count} 个字符串"
                )
                
                messagebox.showinfo("保存成功", message)
                self.status_var.set(f"文件已保存: {os.path.basename(save_path)}")
            except Exception as e:
                messagebox.showerror("错误", f"保存文件失败: {str(e)}")
    
    def export_json(self):
        if not hasattr(self, 'strings') or not self.strings:
            messagebox.showwarning("警告", "没有可导出的字符串数据")
            return
  
        filtered_strings = []
        for s in self.filtered_strings:
            filtered_strings.append(s)

        if not filtered_strings:
            messagebox.showinfo("导出", "没有符合条件的字符串可导出")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="导出JSON文件",
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            export_data = []
            for s in filtered_strings:
                export_data.append({
                    "address": f"0x{s['address']:08X}",
                    "original": s['original'],
                    "translation": s['translation'],
                    "length": s['orig_length']
                })
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
                
            messagebox.showinfo("导出成功", f"已导出 {len(export_data)} 个字符串到: {file_path}")
            self.status_var.set(f"已导出 {len(export_data)} 个字符串")
                
        except Exception as e:
            messagebox.showerror("导出错误", f"导出JSON失败: {str(e)}")
    
    def import_json(self):
    # TO DO：最好还是改一改
        if not hasattr(self, 'strings') or not self.strings:
            messagebox.showwarning("警告", "请先加载文件")
            return
            
        file_path = filedialog.askopenfilename(
            title="导入JSON文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                import_data = json.load(f)
                
            if not isinstance(import_data, list):
                messagebox.showerror("导入错误", "JSON格式不正确，应为字符串列表")
                return
                
            updated_count = 0
            skipped_count = 0
            
            addr_map = {f"0x{s['address']:08X}": s for s in self.strings}
            
            for item in import_data:
                addr = item.get("address", "")
                translation = item.get("translation", "")
                
                if not addr or not translation:
                    skipped_count += 1
                    continue
                    
                target = addr_map.get(addr)
                if not target:
                    skipped_count += 1
                    continue
                    
                trans_bytes = translation.encode('utf-8')
                if len(trans_bytes) > target['orig_length']:
                    skipped_count += 1
                    continue
                    
                target['translation'] = translation
                target['status'] = "已修改"
                updated_count += 1
                
            self.populate_string_list()
            
            message = (
                f"导入完成！\n\n"
                f"更新: {updated_count} 个字符串\n"
                f"跳过: {skipped_count} 个字符串\n\n"
                f"原因: 地址不匹配或翻译过长"
            )
            messagebox.showinfo("导入结果", message)
            self.status_var.set(f"导入完成: 更新 {updated_count} 个字符串")
                
        except Exception as e:
            messagebox.showerror("导入错误", f"导入JSON失败: {str(e)}")

    def show_startup_message(self):
        settings_path = os.path.join(os.path.dirname(sys.argv[0]), "settings.json")

        if os.path.exists(settings_path):
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
                if settings.get("suppress_startup_message"):
                    return
        else:
            settings = {}

        popup = tk.Toplevel(self.root)
        popup.title("提示")
        popup.geometry("400x250")
        popup.configure(bg="#1e293b")
        popup.grab_set()

        message = "使用须知：\n1.这是一个由Python语言制作的辅助本地化工具，本质上为HEX编辑器。\n2.本项目打开.exe后会自动备份.bak文件。\n3.本项目为临时起意，不保证维护性，作者为Cxx（B站 & Github）。\n4.本项目于Github开源。"
        label = tk.Label(popup, text=message, bg="#1e293b", fg="white", font=("Segoe UI", 10), wraplength=360, justify="left")
        label.pack(padx=20, pady=(20, 10), anchor="w")

        suppress_var = tk.BooleanVar()

        check = tk.Checkbutton(
            popup, text="不再提示", variable=suppress_var,
            bg="#1e293b", fg="white", selectcolor="#334155",
            activebackground="#1e293b", activeforeground="white"
        )
        check.pack(pady=(0, 10), anchor="w", padx=20)

        def on_ok():
            if suppress_var.get():
                settings["suppress_startup_message"] = True
                with open(settings_path, "w", encoding="utf-8") as f:
                    json.dump(settings, f)
            popup.destroy()

        ok_btn = ttk.Button(popup, text="确定", command=on_ok)
        ok_btn.pack(pady=(0, 20))


if __name__ == "__main__":
    root = tk.Tk()

    root.option_add("*TCombobox*Listbox*Background", "#334155")
    root.option_add("*TCombobox*Listbox*Foreground", "white")
    root.option_add("*TCombobox*Listbox*Font", ('Segoe UI', 10))
    
    text_tags = {
        "header": {"font": ('Segoe UI', 12, 'bold'), "foreground": "#0ea5e9"},
        "address": {"font": ('Consolas', 10), "foreground": "#f59e0b"},
        "warning": {"foreground": "#ef4444", "font": ('Segoe UI', 10, 'bold')}
    }
    
    app = GamemakerLocalizer(root)
    
    for tag, config in text_tags.items():
        app.preview_text.tag_configure(tag, **config)
        app.hex_text.tag_configure(tag, **config)
    
    root.mainloop()