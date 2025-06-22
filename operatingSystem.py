import os
import requests
import time
import tkinter as tk
from tkinter import *
from tkinter import messagebox, scrolledtext

virus_total_api_scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
virus_total_api_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

virus_total_api_key = "81324c2c02d1a2d8d04e469117380fecbf2269b1450e02e48b852d16932e61c9"

def scan_file(file_path):
    print("Scanning: ", file_path)
    log_text.insert(tk.END, f"Scanning: {file_path}\n")
    log_text.see(tk.END)
    root.update()
    
    try:
        response = send_scan_request(file_path)
        if 'scan_id' not in response:
            log_text.insert(tk.END, f"Error: No scan_id in response for {file_path}\n")
            return
            
        is_virus = get_report(scan_id=response['scan_id'])
        
        if is_virus:
            message = f"⚠️ VIRUS DETECTED!!! Filepath: {file_path}\n"
            log_text.insert(tk.END, message)
        else:
            message = f"✅ {file_path} is clean\n"
            log_text.insert(tk.END, message)
            
        log_text.see(tk.END)
        root.update()
        
    except Exception as e:
        error_msg = f"Error scanning {file_path}: {str(e)}\n"
        log_text.insert(tk.END, error_msg)
        log_text.see(tk.END)
        root.update()

def send_scan_request(file_path):
    params = {'apikey': virus_total_api_key}
    
    try:
        with open(file_path, 'rb') as file_content:
            filename = os.path.basename(file_path)
            files = {'file': (filename, file_content)}
            response = requests.post(virus_total_api_scan_url, files=files, params=params)
            
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
            
        return response.json()
    except Exception as e:
        raise Exception(f"Failed to send scan request: {str(e)}")

def get_report(scan_id, max_retries=10):
    params = {'apikey': virus_total_api_key, 'resource': scan_id}
    
    for attempt in range(max_retries):
        try:
            response = requests.get(virus_total_api_report_url, params=params)
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            result = response.json()
            
            # Check if still being analyzed
            if result.get("verbose_msg") == "Your resource is queued for analysis" or result.get("response_code") == -2:
                log_text.insert(tk.END, f"Waiting for analysis... (attempt {attempt + 1}/{max_retries})\n")
                log_text.see(tk.END)
                root.update()
                time.sleep(10)  # Wait longer between retries
                continue
            
            # Check if scan completed successfully
            if result.get("response_code") == 1:
                positives = result.get("positives", 0)
                total = result.get("total", 0)
                log_text.insert(tk.END, f"Scan complete: {positives}/{total} engines detected threats\n")
                return positives > 0
            else:
                log_text.insert(tk.END, f"Scan failed or file not found in database\n")
                return False
                
        except Exception as e:
            log_text.insert(tk.END, f"Error getting report: {str(e)}\n")
            return False
    
    log_text.insert(tk.END, f"Timeout waiting for scan results\n")
    return False

def iterate_files(folder_path):
    if not os.path.exists(folder_path):
        messagebox.showerror("Error", f"Path does not exist: {folder_path}")
        return
    
    file_count = 0
    for root_dir, dirs, files in os.walk(folder_path):
        for filename in files:
            full_path = os.path.join(root_dir, filename)
            
            # Skip very large files (>32MB for free API)
            try:
                if os.path.getsize(full_path) > 32 * 1024 * 1024:
                    log_text.insert(tk.END, f"Skipping large file: {full_path}\n")
                    continue
            except:
                continue
                
            scan_file(full_path)
            file_count += 1
            
            # Add delay to respect API rate limits (4 requests per minute for free tier)
            time.sleep(16)  # 60 seconds / 4 requests = 15 seconds + buffer
    
    log_text.insert(tk.END, f"\n FINISHED RUNNING THE PROGRAM!! \n Processed {file_count} files.\n")
    messagebox.showinfo("Complete", f"Scan complete! Processed {file_count} files.\nFINISHED RUNNING THE PROGRAM!!")

def submit():
    path = path_var.get().strip()
    if not path:
        messagebox.showerror("Error", "Please enter a folder path")
        return
    
    # Clear previous results
    log_text.delete(1.0, tk.END)
    
    # Disable submit button during scan
    sub_btn.config(state='disabled')
    
    try:
        iterate_files(folder_path=path)
    finally:
        # Re-enable submit button
        sub_btn.config(state='normal')

# Create main window
root = tk.Tk()
root.title("VirusTotal Scanner")
root.geometry("800x600")

# Input section
input_frame = tk.Frame(root)
input_frame.pack(pady=10, padx=10, fill='x')

path_var = tk.StringVar()
path_label = tk.Label(input_frame, text='Path of the starting folder:', font=('calibre', 10, 'bold'))
path_entry = tk.Entry(input_frame, textvariable=path_var, font=('calibre', 10, 'normal'), width=50)
sub_btn = tk.Button(input_frame, text='Start Scan', command=submit, bg='#4CAF50', fg='white', font=('calibre', 10, 'bold'))

path_label.grid(row=0, column=0, sticky='w', padx=(0, 10))
path_entry.grid(row=0, column=1, sticky='ew', padx=(0, 10))
sub_btn.grid(row=0, column=2)

input_frame.columnconfigure(1, weight=1)

# Log section
log_frame = tk.Frame(root)
log_frame.pack(pady=10, padx=10, fill='both', expand=True)

log_label = tk.Label(log_frame, text='Scan Results:', font=('calibre', 10, 'bold'))
log_label.pack(anchor='w')

log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80, font=('consolas', 9))
log_text.pack(fill='both', expand=True)

# Add instructions
instructions = """Instructions:
1. Enter the full path to the folder you want to scan
2. Click 'Start Scan' to begin
3. The scanner will check all files in the folder and subfolders
4. Results will appear in the log below

Note: This uses the free VirusTotal API with rate limits (4 requests/minute)
Large scans may take considerable time."""

log_text.insert(tk.END, instructions + "\n" + "="*60 + "\n\n")



root.mainloop()