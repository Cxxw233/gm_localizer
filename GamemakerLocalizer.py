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

class GamemakerLocalizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Gamemaker YYC 本地化辅助工具 Debug")
        self.root.geometry("1000x800")
        self.root.configure(bg="#2c3e50")
        
        self.file_path = ""
        self.original_data = bytearray()
        self.modified_data = bytearray()
        self.strings = []
        self.backup_created = False
        self.processing = False
        self.running = True
        
        # 弃用
        self.blacklist_prefixes = [
            'gml_', 'time_', 'ds_', 'image_', 'view_', 'keyboard_', 'window_', 
            'string_', 'draw_', 'sprite_', 'file_', 'room_', 'object_', 'variable_', 
            'audio_', 'instance_', 'camera_', 'surface_', 'move_', 'array_', 'is_', 
            'lengthdir_', 'point_', 'dot_', 'mp_', 'collision_', 'position_', 
            'game_', 'display_', 'skeleton_', 'date_', 'layer_', 'tilemap_', 
            'tile_', 'background_', 'caption_', 'current_', 'delta_', 'event_', 
            'mouse_', 'os_', 'pointer_', 'shader_', 'vk_', 'gp_', 'ev_', 'cr_', 
            'pt_', 'ps_', 'fa_', 'dll_', 'ef_', 'phy_', 'matrix_', 'lb_', 'ov_', 
            'buffer_', 'video_', 'xboxlive_', 'device_', 'browser_', 'of_', 
            'leaderboard_', 'achievement_', 'asset_', 'kbv_', 'filename_', 
            'http_', 'ini_', 'parameter_', 'json_', 'gesture_', 'invalid', 
            'texturegroup_', 'font_', 'gpu_', 'part_', 'effect_', 'physics_', 
            'gamepad_', 'steam_', 'push_', 'vertex_'
        ]
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.layout('Custom.TCheckbutton',
            [('Checkbutton.padding',
              {'children': [
                  ('Checkbutton.indicator', {
                      'side': 'left', 
                      'sticky': '',
                      'children': [
                          ('CustomCheckbutton.indicator', {'side': 'left', 'sticky': ''})
                      ]
                  }),
                  ('Checkbutton.focus', {
                      'side': 'left', 
                      'sticky': '',
                      'children': [
                          ('Checkbutton.label', {'sticky': 'nswe'})
                      ]
                  })
              ],
              'sticky': 'nswe'})])
        
        self.style.configure('Custom.TCheckbutton', 
                            background='#2c3e50', 
                            foreground='#ecf0f1',
                            font=('Arial', 10),
                            indicatormargin=2,
                            indicatordiameter=15)
        
        self.style.map('Custom.TCheckbutton',
            background=[('active', '#2c3e50'), ('selected', '#2c3e50')],
            foreground=[('active', '#ecf0f1'), ('selected', '#ecf0f1')],
            indicatorcolor=[
                ('selected', '#3498db'),
                ('!selected', '#7f8c8d')
            ])
        
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def on_close(self):
        self.running = False
        self.root.destroy()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        top_frame = ttk.LabelFrame(main_frame, text="文件操作", padding=10)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(top_frame, text="游戏文件:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.file_entry = ttk.Entry(top_frame, width=70)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")

        self.browse_btn = ttk.Button(top_frame, text="浏览...", command=self.browse_file)
        self.browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.load_btn = ttk.Button(top_frame, text="加载文件", command=self.load_file)
        self.load_btn.grid(row=0, column=3, padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(top_frame, variable=self.progress_var, 
                                    mode='determinate', length=300)
        self.progress.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="we")
        self.progress_label = ttk.Label(top_frame, text="就绪", font=('Arial', 9))
        self.progress_label.grid(row=2, column=0, columnspan=4, padx=5, pady=(0, 5))
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        list_frame = ttk.Frame(notebook, padding=10)
        notebook.add(list_frame, text="字符串列表")
        
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
    
        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_entry.bind('<KeyRelease>', self.filter_strings)
        
        btn_frame = ttk.Frame(search_frame)
        btn_frame.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.export_btn = ttk.Button(btn_frame, text="导出JSON", command=self.export_json)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.import_btn = ttk.Button(btn_frame, text="导入JSON", command=self.import_json)
        self.import_btn.pack(side=tk.LEFT, padx=5)
        
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
        
        ttk.Label(trans_frame, text="原始文本:").pack(anchor="w", pady=(5, 0))
        self.original_text = scrolledtext.ScrolledText(
            trans_frame, height=5, wrap=tk.WORD, bg="#34495e", fg="white", 
            font=('Arial', 10), state='disabled'
        )
        self.original_text.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(trans_frame, text="翻译文本:").pack(anchor="w", pady=(10, 0))
        self.translation_text = scrolledtext.ScrolledText(
            trans_frame, height=5, wrap=tk.WORD, bg="#34495e", fg="white", 
            font=('Arial', 10)
        )
        self.translation_text.pack(fill=tk.X, padx=5, pady=5)
        self.translation_text.bind('<KeyRelease>', self.on_translation_change)
        
        ttk.Label(trans_frame, text="十六进制预览:").pack(anchor="w", pady=(10, 0))
        self.hex_text = tk.Text(
            trans_frame, height=5, wrap=tk.NONE, bg="#34495e", fg="#f39c12", 
            font=('Courier New', 9), state='disabled'
        )
        self.hex_text.pack(fill=tk.X, padx=5, pady=5)
        
        btn_frame = ttk.Frame(trans_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        apply_btn = ttk.Button(btn_frame, text="应用翻译", command=self.apply_translation)
        apply_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(btn_frame, text="清除", command=self.clear_translation)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.length_var = tk.StringVar(value="原始长度: 0 字节 | 翻译长度: 0 字节")
        ttk.Label(trans_frame, textvariable=self.length_var, font=('Arial', 9)).pack(anchor="w")
        
        preview_frame = ttk.Frame(notebook, padding=10)
        notebook.add(preview_frame, text="修改预览")
        
        self.preview_text = scrolledtext.ScrolledText(
            preview_frame, wrap=tk.WORD, bg="#34495e", fg="white", 
            font=('Courier New', 9), state='disabled'
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        bottom_frame = ttk.Frame(main_frame, padding=10)
        bottom_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.save_btn = ttk.Button(bottom_frame, text="保存修改", command=self.save_file)
        self.save_btn.pack(side=tk.RIGHT, padx=5)
        
        self.preview_btn = ttk.Button(bottom_frame, text="生成预览", command=self.generate_preview)
        self.preview_btn.pack(side=tk.RIGHT, padx=5)

        btn_frame = ttk.Frame(trans_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.apply_btn = ttk.Button(btn_frame, text="应用翻译", command=self.apply_translation)
        self.apply_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="清除", command=self.clear_translation)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(
            self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W,
            font=('Arial', 9)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.translation_text.focus()

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
        self.strings = []
        data = self.original_data
        
        pattern = re.compile(b'[\x20-\x7E]{4,}')
        
        pos = 0
        total = len(data)
        found = 0
        
        while pos < total and self.running:
            match = pattern.search(data, pos)
            if not match:
                break
                
            start = match.start()
            end = match.end()
            
            if end < total and data[end] == 0:
                try:
                    text = data[start:end].decode('utf-8')
                    if self.is_likely_user_string(text):
                        self.strings.append({
                            'address': start,
                            'original': text,
                            'translation': "",
                            'status': "未修改",
                            'orig_length': end - start
                        })
                        found += 1
                        
                        if found % 100 == 0:
                            self.update_progress(10 + (pos/total)*80, 
                                               f"已找到 {found} 个字符串...")
                    
                    pos = end + 1
                    continue
                except UnicodeDecodeError:
                    pass
                    
            pos = end + 1
        
        self.strings.sort(key=lambda x: x['address'])
        self.update_progress(90, f"找到 {len(self.strings)} 个字符串，正在处理...")

    def is_likely_user_string(self, text):
        if '_' in text or '$' in text or '&' in text or '@' in text:
            return False
            
        return True
    
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
                self.status_var.set(f"没有找到匹配 “{search_term}” 的字符串")

        self.populate_tree_from_list(self.filtered_strings)

    def populate_tree_from_list(self, string_list):
        if not self.running or not self.root.winfo_exists():
            return

        self.tree.delete(*self.tree.get_children())

        for i, s in enumerate(string_list):
            self.tree.insert("", "end", values=(
                f"0x{s['address']:08X}",
                s['original'],
                s['translation'],
                s['status'],
                s['orig_length']
            ))

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
        original = values[1]
        translation = values[2]
        orig_length = int(values[4])
        
        self.original_text.config(state='normal')
        self.original_text.delete(1.0, tk.END)
        self.original_text.insert(tk.END, original)
        self.original_text.config(state='disabled')
        
        self.translation_text.delete(1.0, tk.END)
        self.translation_text.insert(tk.END, translation)
        
        self.update_hex_preview(original, translation, orig_length)
        
        self.current_item = item
        self.current_address = address
        self.current_orig_length = orig_length
    
    def update_hex_preview(self, original, translation, orig_length):
        self.hex_text.config(state='normal')
        self.hex_text.delete(1.0, tk.END)
        
        try:
            orig_hex = binascii.hexlify(original.encode('utf-8')).decode('utf-8')
            orig_formatted = ' '.join(orig_hex[i:i+2].upper() for i in range(0, len(orig_hex), 2))
            
            trans_hex = ""
            trans_formatted = ""
            if translation:
                try:
                    trans_hex = binascii.hexlify(translation.encode('utf-8')).decode('utf-8')
                    trans_formatted = ' '.join(trans_hex[i:i+2].upper() for i in range(0, len(trans_hex), 2))
                except:
                    pass
            
            self.hex_text.insert(tk.END, "原始: " + orig_formatted + "\n")
            self.hex_text.insert(tk.END, "翻译: " + trans_formatted + "\n\n")
            
            orig_bytes = len(original.encode('utf-8'))
            trans_bytes = len(translation.encode('utf-8')) if translation else 0
            self.length_var.set(f"原始长度: {orig_bytes} 字节 | 翻译长度: {trans_bytes} 字节 | 可用空间: {orig_length} 字节")
            
            if translation and trans_bytes > orig_length:
                self.hex_text.insert(tk.END, "警告: 翻译文本超过可用空间！\n", "warning")
        except Exception as e:
            self.hex_text.insert(tk.END, f"错误: {str(e)}")
        
        self.hex_text.config(state='disabled')
    
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
        original = values[1]
        
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
    
    def generate_preview(self):
        modified_count = sum(1 for s in self.strings if s['status'] == "已修改")
        if modified_count == 0:
            messagebox.showinfo("预览", "没有修改需要预览")
            return
        
        self.preview_text.config(state='normal')
        self.preview_text.delete(1.0, tk.END)
        
        self.preview_text.insert(tk.END, "Gamemaker YYC 本地化修改预览报告\n", "header")
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
            if '_' not in s['original'] and '@' not in s['original']:
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

if __name__ == "__main__":
    root = tk.Tk()

    root.option_add("*TCombobox*Listbox*Background", "#34495e")
    root.option_add("*TCombobox*Listbox*Foreground", "white")
    root.option_add("*TCombobox*Listbox*Font", ('Arial', 10))
    
    text_tags = {
        "header": {"font": ('Arial', 12, 'bold'), "foreground": "#3498db"},
        "address": {"font": ('Courier New', 10), "foreground": "#f39c12"},
        "warning": {"foreground": "#e74c3c", "font": ('Arial', 10, 'bold')}
    }
    
    app = GamemakerLocalizer(root)
    
    for tag, config in text_tags.items():
        app.preview_text.tag_configure(tag, **config)
        app.hex_text.tag_configure(tag, **config)
    
    root.mainloop()