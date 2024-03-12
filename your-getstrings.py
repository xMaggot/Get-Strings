import os
import hashlib
import datetime
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import Tk, Label, Button, PhotoImage
import pefile
import requests
from io import BytesIO
from PIL import Image, ImageTk
import customtkinter
from tkinter import *
import customtkinter
from PIL import Image, ImageTk

def extract_strings():
    if not pe_file:
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Not Found!")
        result_text.config(state=tk.DISABLED)
        return

    file_name = os.path.basename(pe_file)
    file_size = os.path.getsize(pe_file)
    
    md5_hash = hashlib.md5(open(pe_file, 'rb').read()).hexdigest()

    sha256_hash = hashlib.sha256(open(pe_file, 'rb').read()).hexdigest()

    file_extension = os.path.splitext(pe_file)[1].lower()

    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)

    if file_extension in ('.exe', '.dll'):
        pe = pefile.PE(pe_file)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        timestamp_dt = datetime.datetime.utcfromtimestamp(timestamp)
        timestamp_str = timestamp_dt.strftime("%Y/%m/%d:%H:%M:%S")
        DPS_string = "!" + timestamp_str
        pcasvc_string = (hex(pe.OPTIONAL_HEADER.SizeOfImage))

        result_text.insert(tk.END, f"name: {file_name}\n")
        result_text.insert(tk.END, f"size:={file_size}\n")
        result_text.insert(tk.END, f"MD5: {md5_hash}\n")
        result_text.insert(tk.END, f"SHA-256: {sha256_hash}\n")
        result_text.insert(tk.END, f"DPS: {DPS_string}\n")
        result_text.insert(tk.END, f"PcaSvc: {pcasvc_string}")
    else:
        result_text.insert(tk.END, f"name: {file_name}\n")
        result_text.insert(tk.END, f"size:={file_size}\n")
        result_text.insert(tk.END, f"MD5: {md5_hash}\n")
        result_text.insert(tk.END, f"SHA-256: {sha256_hash}\n")
        result_text.insert(tk.END, f"PcaSvc: {pcasvc_string}")

    result_text.config(state=tk.DISABLED)

def browse_file():
    global pe_file
    pe_file = filedialog.askopenfilename()

def extract():
    if not pe_file:
        return
    extract_strings()

def fetch_image(url):
    response = requests.get(url)
    img_data = response.content
    img = Image.open(BytesIO(img_data))
    return ImageTk.PhotoImage(img)

def fetch_icon(url):
    response = requests.get(url)
    icon_data = response.content
    icon = Image.open(BytesIO(icon_data))
    return ImageTk.PhotoImage(icon)

root = tk.Tk()
width = 600
height = 280
x_offset = (root.winfo_screenwidth() - width) // 2
y_offset = (root.winfo_screenheight() - height) // 2
root.geometry(f"{width}x{height}+{x_offset}+{y_offset}")
root.config(bg="black")
root.minsize(width, height)
root.maxsize(width, height)
root.resizable(width=False, height=False)
root.title("NAME Program")
icon_url = "https://yoururl/logo.ico" ##### URL .ICO 
icon = fetch_icon(icon_url)
root.iconphoto(True, icon)
img_bg = fetch_image("https://yourbackground/background.png") ##### URL .PNG

lab_bg = Label(root, image=img_bg)
lab_bg.pack()

button = customtkinter.CTkButton(master=root, width=80, height=25, text="SEARCH", fg_color="#100811", text_color="white", corner_radius=15, hover_color="#8500B2", border_width=1, border_color="white", command=browse_file)
button.place(relx=0.85, rely=0.1, anchor=CENTER)

button = customtkinter.CTkButton(master=root, width=80, height=25, text="STRING", fg_color="#100811", text_color="white", corner_radius=15, hover_color="#8500B2", border_width=1, border_color="white", command=extract_strings)
button.place(relx=0.85, rely=0.22, anchor=CENTER)

result_text = tk.Text(root, wrap=tk.WORD, state=tk.DISABLED, height=8, width=43, bg="black", fg="white", font=("Calibri", 12))
result_text.place(x=226, y=81)

root.mainloop()
