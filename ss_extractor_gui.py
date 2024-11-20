import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime
import threading
import pyperclip
import os
import yaml
from urllib.parse import quote

class SSExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SS Node Extractor")
        self.root.geometry("600x400")
        
        # 设置窗口图标
        self.setup_ui()
        
    def setup_ui(self):
        # 标题区域
        title_frame = ttk.Frame(self.root)
        title_frame.pack(pady=10)
        
        ttk.Label(title_frame, text="SS Node Extractor", font=('Arial', 16, 'bold')).pack()
        ttk.Label(title_frame, text=f"Version: 1.0").pack()
        ttk.Label(title_frame, text="作者: 木子李").pack()
        
        # 按钮区域
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.extract_btn = ttk.Button(button_frame, text="提取节点", command=self.start_extraction)
        self.extract_btn.pack(side=tk.LEFT, padx=5)
        
        self.copy_btn = ttk.Button(button_frame, text="复制节点", command=self.copy_nodes, state=tk.DISABLED)
        self.copy_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(button_frame, text="保存到文件", command=self.save_to_file, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        # 添加新的转换按钮
        convert_frame = ttk.Frame(self.root)
        convert_frame.pack(pady=5)
        
        self.clash_btn = ttk.Button(convert_frame, text="保存为Clash配置", 
                                   command=self.save_clash_config, state=tk.DISABLED)
        self.clash_btn.pack(side=tk.LEFT, padx=5)
        
        self.base64_btn = ttk.Button(convert_frame, text="保存为Base64订阅", 
                                    command=self.save_base64_subscription, state=tk.DISABLED)
        self.base64_btn.pack(side=tk.LEFT, padx=5)
        
        # 进度条
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=10)
        
        # 结果显示区域
        self.result_text = tk.Text(self.root, height=15, width=60)
        self.result_text.pack(padx=20, pady=10)
        
        self.nodes = []

    def decrypt_data(self, encrypted_data, key, iv):
        decryptor = pyaes.AESModeOfOperationCBC(key, iv=iv)
        decrypted = b''.join(decryptor.decrypt(encrypted_data[i:i+16]) for i in range(0, len(encrypted_data), 16))
        return decrypted[:-decrypted[-1]]

    def extract_nodes(self):
        try:
            url = 'http://api.skrapp.net/api/serverlist'
            headers = {
                'accept': '/',
                'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
                'appversion': '1.3.1',
                'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
                'content-type': 'application/x-www-form-urlencoded',
                'Cookie': 'PHPSESSID=fnffo1ivhvt0ouo6ebqn86a0d4'
            }
            data = {'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'}
            key = b'65151f8d966bf596'
            iv = b'88ca0f0ea1ecf975'

            response = requests.post(url, headers=headers, data=data)
            
            if response.status_code == 200:
                encrypted_text = response.text.strip()
                encrypted_data = binascii.unhexlify(encrypted_text)
                decrypted_data = self.decrypt_data(encrypted_data, key, iv)
                nodes_data = json.loads(decrypted_data)
                
                self.nodes = []
                for node in nodes_data['data']:
                    ss_url = f"aes-256-cfb:{node['password']}@{node['ip']}:{node['port']}"
                    ss_base64 = base64.b64encode(ss_url.encode('utf-8')).decode('utf-8')
                    ss_link = f"ss://{ss_base64}#{node['title']}"
                    self.nodes.append(ss_link)
                
                self.root.after(0, self.update_ui_after_extraction)
            else:
                self.root.after(0, lambda: self.show_error("请求失败"))
        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"错误: {str(e)}"))

    def start_extraction(self):
        self.extract_btn.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)
        self.result_text.delete(1.0, tk.END)
        self.progress.start()
        
        thread = threading.Thread(target=self.extract_nodes)
        thread.daemon = True
        thread.start()

    def update_ui_after_extraction(self):
        self.progress.stop()
        self.extract_btn.config(state=tk.NORMAL)
        self.copy_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.NORMAL)
        self.clash_btn.config(state=tk.NORMAL)  # 启用Clash配置按钮
        self.base64_btn.config(state=tk.NORMAL)  # 启用Base64订阅按钮
        
        self.result_text.delete(1.0, tk.END)
        for node in self.nodes:
            self.result_text.insert(tk.END, node + '\n')

    def copy_nodes(self):
        nodes_text = '\n'.join(self.nodes)
        pyperclip.copy(nodes_text)
        self.show_message("节点已复制到剪贴板")

    def save_to_file(self):
        if not self.nodes:
            return
            
        filename = f"ss_nodes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.nodes))
        self.show_message(f"节点已保存到文件: {filename}")

    def show_message(self, message):
        tk.messagebox.showinfo("提示", message)

    def show_error(self, message):
        self.progress.stop()
        self.extract_btn.config(state=tk.NORMAL)
        tk.messagebox.showerror("错误", message)

    def save_clash_config(self):
        if not self.nodes:
            self.show_error("没有可用的节点")
            return
        
        try:
            # 将所有节点合并成一个字符串并进行 URL 编码
            nodes_text = '|'.join(self.nodes)
            encoded_nodes = quote(nodes_text)
            
            # 构建转换网页 URL
            web_url = (
                "https://suburl.v1.mk/"
                f"#/sub?target=clash"  # 使用 #/sub 而不是 /sub
                f"&url={encoded_nodes}"
                "&insert=false"
                "&config=https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini"
                "&emoji=true"
                "&list=false"
                "&udp=false"
                "&tfo=false"
                "&expand=true"
                "&scv=false"
                "&fdn=false"
                "&new_name=true"
            )
            
            # 使用默认浏览器打开转换网页
            import webbrowser
            webbrowser.open(web_url)
            self.show_message("已打开转换网页，请点击下载按钮保存配置文件")
                
        except Exception as e:
            self.show_error(f"打开网页失败: {str(e)}")

    def convert_to_base64(self):
        if not self.nodes:
            self.show_error("没有可用的节点")
            return
        
        # 确保每个节点都是单独的一行，并移除空行
        nodes_text = '\n'.join(node.strip() for node in self.nodes if node.strip())
        # 确保最后有一个换行符，这对某些客户���很重要
        if not nodes_text.endswith('\n'):
            nodes_text += '\n'
        return base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8')

    def save_base64_subscription(self):
        try:
            # 将节点转换为Base64格式
            nodes_text = '\n'.join(node.strip() for node in self.nodes if node.strip())
            if not nodes_text.endswith('\n'):
                nodes_text += '\n'
            
            # 进行Base64编码
            base64_content = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8')
            
            # 保存文件
            filename = f"subscription_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                f.write(base64_content)
            
            # 验证文件
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    test_content = f.read().strip()
                    decoded = base64.b64decode(test_content).decode('utf-8')
                    if not any(line.startswith('ss://') for line in decoded.splitlines()):
                        raise ValueError("订阅内容格式错误")
            except Exception as e:
                os.remove(filename)
                raise ValueError(f"订阅文件验证失败: {str(e)}")
                
            self.show_message(f"Base64订阅已保存到文件: {filename}\n"
                             f"共 {len(self.nodes)} 个节点\n"
                             "可直接导入到V2rayN使用")
            
        except Exception as e:
            self.show_error(f"生成Base64订阅失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SSExtractorGUI(root)
    root.mainloop() 
