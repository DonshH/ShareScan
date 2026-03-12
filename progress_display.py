import socket
import json
import tkinter as tk
from tkinter import ttk
import threading
import time

def connect_with_retry(host='127.0.0.1', port=9999, retries=20, delay=1):
    for i in range(retries):
        try:
            s = socket.socket()
            s.connect((host, port))
            return s
        except ConnectionRefusedError:
            print(f"Waiting for scanner to start... ({i+1}/{retries})")
            time.sleep(delay)
    raise RuntimeError("Could not connect to scanner after multiple attempts")


class ScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Share Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg='#1e1e1e')

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", background='#00ff00', troughcolor='#333333')

        # IP Progress
        tk.Label(root, text="IPs Scanned", fg='white', bg='#1e1e1e', font=('Consolas', 10)).pack(anchor='w', padx=20, pady=(20,0))
        self.ip_label = tk.Label(root, text="0/0", fg='#aaaaaa', bg='#1e1e1e', font=('Consolas', 9))
        self.ip_label.pack(anchor='w', padx=20)
        self.ip_bar = ttk.Progressbar(root, length=760, mode='determinate')
        self.ip_bar.pack(padx=20, pady=(0,10))

        # Share Progress
        tk.Label(root, text="Shares Scanned", fg='white', bg='#1e1e1e', font=('Consolas', 10)).pack(anchor='w', padx=20)
        self.share_label = tk.Label(root, text="0/0", fg='#aaaaaa', bg='#1e1e1e', font=('Consolas', 9))
        self.share_label.pack(anchor='w', padx=20)
        self.share_bar = ttk.Progressbar(root, length=760, mode='determinate')
        self.share_bar.pack(padx=20, pady=(0,10))

        # File Progress
        tk.Label(root, text="Files Scanned", fg='white', bg='#1e1e1e', font=('Consolas', 10)).pack(anchor='w', padx=20)
        self.file_label = tk.Label(root, text="0/0", fg='#aaaaaa', bg='#1e1e1e', font=('Consolas', 9))
        self.file_label.pack(anchor='w', padx=20)
        self.file_bar = ttk.Progressbar(root, length=760, mode='determinate')
        self.file_bar.pack(padx=20, pady=(0,10))

        # Info section
        tk.Frame(root, bg='#333333', height=1).pack(fill='x', padx=20, pady=10)
        self.share_name_label = tk.Label(root, text="Current Share: ", fg='#00aaff', bg='#1e1e1e', font=('Consolas', 9))
        self.share_name_label.pack(anchor='w', padx=20)
        self.dir_label = tk.Label(root, text="Total Directories: ...", fg='#00aaff', bg='#1e1e1e', font=('Consolas', 9))
        self.dir_label.pack(anchor='w', padx=20)

        # Log
        tk.Frame(root, bg='#333333', height=1).pack(fill='x', padx=20, pady=10)
        tk.Label(root, text="Recent Activity", fg='white', bg='#1e1e1e', font=('Consolas', 10)).pack(anchor='w', padx=20)
        self.log_box = tk.Text(root, bg='#0d0d0d', fg='#00ff00', font=('Consolas', 8), height=12, state='disabled', wrap='none')
        self.log_box.pack(fill='both', padx=20, pady=(0,20), expand=True)

    def update_ip(self, current, total):
        self.ip_label.config(text=f"{current}/{total}")
        self.ip_bar['maximum'] = total
        self.ip_bar['value'] = current

    def update_share(self, current, total, share=''):
        self.share_label.config(text=f"{current}/{total}")
        self.share_bar['maximum'] = total
        self.share_bar['value'] = current
        self.share_name_label.config(text=f"Current Share: {share}")

    def update_file(self, current, total):
        self.file_label.config(text=f"{current}/{total}")
        self.file_bar['maximum'] = total
        self.file_bar['value'] = current

    def update_dir_count(self, count, path=''):
        self.dir_label.config(text=f"Total Directories in {path}: {count}")

    def append_log(self, message):
        self.log_box.config(state='normal')
        self.log_box.insert('end', message + '\n')
        self.log_box.see('end')
        self.log_box.config(state='disabled')

def listen(ui, root):
    s = connect_with_retry()
    f = s.makefile()

    while True:
        line = f.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
            msg_type = msg.get('type')

            if msg_type == 'ip_progress':
                root.after(0, ui.update_ip, msg['current'], msg['total'])
            elif msg_type == 'share_progress':
                root.after(0, ui.update_share, msg['current'], msg['total'], msg.get('share', ''))
            elif msg_type == 'file_progress':
                root.after(0, ui.update_file, msg['current'], msg['total'])
            elif msg_type == 'dir_count':
                root.after(0, ui.update_dir_count, msg['count'], msg.get('path', ''))
            elif msg_type == 'log':
                root.after(0, ui.append_log, msg['message'])

        except json.JSONDecodeError:
            root.after(0, ui.append_log, line)

    s.close()

if __name__ == '__main__':
    root = tk.Tk()
    ui = ScannerUI(root)
    t = threading.Thread(target=listen, args=(ui, root), daemon=True)
    t.start()
    root.mainloop()
