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

class GamemakerLocalizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Gamemaker YYC 本地化辅助工具 v0.1")
        self.root.geometry("1000x800")
        self.root.configure(bg="#2c3e50")
        
        self.file_path = ""
        self.original_data = bytearray()
        self.modified_data = bytearray()
        self.strings = []
        self.backup_created = False
        self.processing = False
        self.search_mode = tk.StringVar(value="normal")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2c3e50')
        self.style.configure('TButton', background='#3498db', foreground='white', 
                            font=('Arial', 10, 'bold'), padding=5)
        self.style.map('TButton', background=[('active', '#2980b9')])
        self.style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1', 
                            font=('Arial', 10))
        self.style.configure('Treeview', background='#34495e', foreground='#ecf0f1', 
                            fieldbackground='#34495e', font=('Arial', 9))
        self.style.map('Treeview', background=[('selected', '#2980b9')])
        self.style.configure('Treeview.Heading', background='#2c3e50', foreground='#ecf0f1',
                            font=('Arial', 10, 'bold'))
        self.style.configure('TEntry', fieldbackground='#34495e', foreground='white', 
                            font=('Arial', 10))
        self.style.configure('TCombobox', fieldbackground='#34495e', foreground='white')
        self.style.configure('TNotebook', background='#2c3e50')
        self.style.configure('TNotebook.Tab', background='#34495e', foreground='#ecf0f1',
                            padding=[10, 5], font=('Arial', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', '#3498db')])
        
        self.create_widgets()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        top_frame = ttk.LabelFrame(main_frame, text="文件操作", padding=10)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(top_frame, text="游戏文件:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.file_entry = ttk.Entry(top_frame, width=70)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")
        
        browse_btn = ttk.Button(top_frame, text="浏览...", command=self.browse_file)
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        load_btn = ttk.Button(top_frame, text="加载文件", command=self.load_file)
        load_btn.grid(row=0, column=3, padx=5, pady=5)
        
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
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        search_entry.bind('<KeyRelease>', self.filter_strings)
        
        mode_frame = ttk.Frame(search_frame)
        mode_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Radiobutton(mode_frame, text="普通", variable=self.search_mode, 
                        value="normal").pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="正则", variable=self.search_mode, 
                        value="regex").pack(side=tk.LEFT, padx=(5, 0))
        
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
        
        save_btn = ttk.Button(bottom_frame, text="保存修改", command=self.save_file)
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        preview_btn = ttk.Button(bottom_frame, text="生成预览", command=self.generate_preview)
        preview_btn.pack(side=tk.RIGHT, padx=5)
        
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
            
            threading.Thread(target=self.load_and_scan_file, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("错误", f"加载文件失败: {str(e)}")
            self.processing = False
    
    def load_and_scan_file(self):
        try:
            with open(self.file_path, "rb") as f:
                self.original_data = bytearray(f.read())
            
            self.modified_data = bytearray(self.original_data)
            
            self.update_progress(10, "扫描字符串...")
            
            self.find_strings()
            
            self.root.after(0, self.populate_string_list)
            
            self.update_progress(100, "文件加载完成")
            self.status_var.set(f"已加载文件: {os.path.basename(self.file_path)}")
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("错误", f"加载文件失败: {str(e)}"))
        finally:
            self.processing = False
    
    def update_progress(self, value, message):
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
        
        while pos < total:
            match = pattern.search(data, pos)
            if not match:
                break
                
            start = match.start()
            end = match.end()
            
            if end < total and data[end] == 0:
                try:
                    text = data[start:end].decode('utf-8')
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

    def is_likely_user_string(self, text):
        if len(text) < 4:
            return False
            
        if re.match(r'^[a-zA-Z]_', text):
            return False
            
        first_char = text[0]
        if first_char in "!@#$%^&()-=+{}[]|:;'\"<>,.?`~":
            return False
            
        return True
    
    def populate_string_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, s in enumerate(self.strings):
            self.tree.insert("", "end", values=(
                f"0x{s['address']:08X}", 
                s['original'], 
                s['translation'], 
                s['status'],
                s['orig_length']
            ))
            
            if i % 100 == 0:
                self.root.update()
        
        self.status_var.set(f"找到 {len(self.strings)} 个可本地化字符串")
    
    def filter_strings(self, event=None):
        search_term = self.search_var.get().lower()
        
        all_items = self.tree.get_children()
        
        if not search_term:
            for item in all_items:
                self.tree.reattach(item, '', 'end')
            return
        
        mode = self.search_mode.get()
        
        for item in all_items:
            values = self.tree.item(item, "values")
            original = values[1].lower()
            translation = values[2].lower() if values[2] else ""
            
            match = False
            if mode == "normal":
                match = search_term in original or search_term in translation
            elif mode == "regex":
                try:
                    pattern = re.compile(search_term, re.IGNORECASE)
                    match = pattern.search(original) or pattern.search(translation)
                except re.error:
                    match = search_term in original or search_term in translation
            
            if match:
                self.tree.reattach(item, '', 'end')
            else:
                self.tree.detach(item)

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
                
                orig_hex = binascii.hexlify(s['original'].encode('utf-8')).decode('utf-8')
                orig_formatted = ' '.join(orig_hex[i:i+2].upper() for i in range(0, len(orig_hex), 2))
                
                trans_hex = binascii.hexlify(s['translation'].encode('utf-8')).decode('utf-8')
                trans_formatted = ' '.join(trans_hex[i:i+2].upper() for i in range(0, len(trans_hex), 2))
                
                self.preview_text.insert(tk.END, f"原始十六进制: {orig_formatted}\n")
                self.preview_text.insert(tk.END, f"修改十六进制: {trans_formatted}\n")
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
