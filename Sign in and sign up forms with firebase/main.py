import tkinter as tk
from tkinter import *
from customtkinter import *
from PIL import ImageTk, Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import firebase_admin
from firebase_admin import db, credentials, initialize_app, storage
import random
import string
import numpy as np
import os
import time
import hmac
import hashlib
import secrets
from tkinter import messagebox
import textwrap
import sys

iterations = 981234

aes_key = bytearray([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

hmackey = bytearray([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
])

def encrypt_data(data):
    iv = [secrets.randbelow(256) for _ in range(16)]
    iv = bytearray(iv)
    cipher1 = AES.new(aes_key, AES.MODE_ECB)
    encrypted_iv = cipher1.encrypt(pad(iv, AES.block_size))
    encrypted_iv = encrypted_iv[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    cphrtstr = ""
    for i in range(16):
        if encrypted_iv[i] < 16:
            cphrtstr += "0"
        cphrtstr += hex(encrypted_iv[i])[2:]
    encrypted_data_length = len(encrypted_data)
    for i in range(encrypted_data_length):
        if encrypted_data[i] < 16:
            cphrtstr += "0"
        cphrtstr += hex(encrypted_data[i])[2:]
    return cphrtstr

def decrypt_data(encrypted_data):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_data)
        iv_bytes = encrypted_bytes[:16]
        data_bytes = encrypted_bytes[16:]
        cipher1 = AES.new(bytes(aes_key), AES.MODE_ECB)
        iv = bytearray(cipher1.decrypt(iv_bytes))
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data_bytes), AES.block_size)
    except Exception as e:
        print(f"Error occurred during decryption: {e}", file=sys.stderr)
        return None

def sign_in_window():
    global username_entry, password_entry
    app = CTk()
    app.geometry("600x403")
    app.resizable(0, 0)
    app.title("Sign In")
    # Center the window on the screen
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    window_width = 600
    window_height = 403

    position_x = int((screen_width - window_width) / 2)
    position_y = int((screen_height - window_height) / 2)

    app.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
    side_img_data = Image.open("./assets/signin.png")
    side_img = CTkImage(dark_image=side_img_data, light_image=side_img_data, size=(300, 403))

    CTkLabel(master=app, text="", image=side_img).pack(expand=True, side="left")

    frame = CTkFrame(master=app, width=300, height=403, fg_color="#F3F9F9", corner_radius=0)
    frame.pack_propagate(0)
    frame.pack(expand=True, side="right")

    CTkLabel(master=frame, text="Shalom!", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 24)).pack(anchor="w", pady=(50, 5), padx=(25, 0))
    CTkLabel(master=frame, text="Sign in to your account", text_color="#7E7E7E", anchor="w", justify="left", font=("Arial Bold", 12)).pack(anchor="w", padx=(25, 0))

    CTkLabel(master=frame, text="Username:", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 14), compound="left").pack(anchor="w", pady=(26, 0), padx=(25, 0))
    username_entry = CTkEntry(master=frame, width=225, fg_color="#F3F9F9", border_color="#26252A", border_width=1, text_color="#26252A")
    username_entry.pack(anchor="w", padx=(25, 0))

    CTkLabel(master=frame, text="Password:", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 14), compound="left").pack(anchor="w", pady=(21, 0), padx=(25, 0))
    password_entry = CTkEntry(master=frame, width=225, fg_color="#F3F9F9", border_color="#26252A", border_width=1, text_color="#26252A", show="*")
    password_entry.pack(anchor="w", padx=(25, 0))

    CTkButton(master=frame, text="Sign in", fg_color="#222126", hover_color="#26e1e1", font=("Arial Bold", 12), text_color="#F3F9F9", width=225, command=lambda: sign_in_action(username_entry, password_entry, app)).pack(anchor="w", pady=(40, 0), padx=(25, 0))

    dnthal1 = CTkLabel(master=frame, text="Don't have an account?", text_color="#7E7E7E", font=("Arial Bold", 12))
    dnthal1.place(x=25, y=350)
    signuplabel = CTkLabel(master=frame, text="Sign Up", text_color="#26e1e1", font=("Arial Bold", 12, "underline"))
    signuplabel.place(x=162, y=350)
    signuplabel.bind("<Button-1>", lambda e: open_signup_form(app))
    signuplabel.bind("<Enter>", lambda e: e.widget.config(cursor="hand2"))
    signuplabel.bind("<Leave>", lambda e: e.widget.config(cursor=""))

    app.mainloop()

def sign_in_action(username_entry, password_entry, form):
    username = username_entry.get()
    password = password_entry.get()
    unhash = hash_string(username)
    if db.reference("/" + unhash).get() == None:
        messagebox.showerror("User doesn't exist", "Can't find user with that username.\nPlease, enter a different username and try again.")
    else:
        string_salt = db.reference("/salt" + unhash).get()
        salt = [int(string_salt[i:i+2], 16) for i in range(0, len(string_salt), 2)]
        derived_key = derive_key_with_pbkdf2(password, salt, 96)
        global aes_key
        global hmackey
        aes_key = derived_key[:32]
        hmackey = derived_key[32:64]
        bytes_for_mp = derived_key[64:]
        ciphertext = db.reference("/" + unhash).get()
        if bytes_for_mp == decrypt_data(ciphertext):
            messagebox.showinfo("Success", username + " signed in successfully!")
            form.destroy()
        else:
            messagebox.showerror("Can't log in", "Wrong password.\nPlease, enter a different password and try again.")


def open_signup_form(root):
    signup_form = CTkToplevel(root)
    signup_form.geometry("600x403")
    signup_form.resizable(0, 0)
    signup_form.title("Sign Up")

    side_img_data = Image.open("./assets/signup.png")
    side_img = CTkImage(dark_image=side_img_data, light_image=side_img_data, size=(300, 403))

    CTkLabel(master=signup_form, text="", image=side_img).pack(expand=True, side="left")

    frame = CTkFrame(master=signup_form, width=300, height=403, fg_color="#F3F9F9", corner_radius=0)
    frame.pack_propagate(0)
    frame.pack(expand=True, side="right")

    CTkLabel(master=frame, text="Sign Up", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 24)).pack(anchor="w", pady=(50, 5), padx=(25, 0))
    CTkLabel(master=frame, text="Create an account", text_color="#7E7E7E", anchor="w", justify="left", font=("Arial Bold", 12)).pack(anchor="w", padx=(25, 0))

    CTkLabel(master=frame, text="Username:", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 14), compound="left").pack(anchor="w", pady=(10, 0), padx=(25, 0))
    username_entry_signup = CTkEntry(master=frame, width=225, fg_color="#F3F9F9", border_color="#26252A", border_width=1, text_color="#26252A")
    username_entry_signup.pack(anchor="w", padx=(25, 0))

    CTkLabel(master=frame, text="Password:", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 14), compound="left").pack(anchor="w", pady=(10, 0), padx=(25, 0))
    password_entry_signup = CTkEntry(master=frame, width=225, fg_color="#F3F9F9", border_color="#26252A", border_width=1, text_color="#26252A", show="*")
    password_entry_signup.pack(anchor="w", padx=(25, 0))

    CTkLabel(master=frame, text="Confirm Password:", text_color="#26252A", anchor="w", justify="left", font=("Arial Bold", 14), compound="left").pack(anchor="w", pady=(10, 0), padx=(25, 0))
    confirm_password_entry_signup = CTkEntry(master=frame, width=225, fg_color="#F3F9F9", border_color="#26252A", border_width=1, text_color="#26252A", show="*")
    confirm_password_entry_signup.pack(anchor="w", padx=(25, 0))

    CTkButton(master=frame, text="Sign Up", fg_color="#222126", hover_color="#26e1e1", font=("Arial Bold", 12), text_color="#F3F9F9", width=225, command=lambda: create_user(username_entry_signup, password_entry_signup, confirm_password_entry_signup, signup_form)).pack(anchor="w", pady=(20, 0), padx=(25, 0))

def create_user(username_entry, password_entry, confirm_password_entry, form):
    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    unhash = hash_string(username)
    if db.reference("/" + unhash).get() == None:
        if password == confirm_password:
            salt = [secrets.randbelow(256) for _ in range(16)]
            string_salt = ''.join(f'{x:02x}' for x in salt)
            db.reference("/").update({"salt"  + unhash: string_salt})
            derived_key = derive_key_with_pbkdf2(password, salt, 96)
            global aes_key
            aes_key = derived_key[:32]
            bytes_for_mp = derived_key[64:]
            encr_ver_hash = encrypt_data(bytes_for_mp)
            db.reference("/").update({unhash: encr_ver_hash})
            if db.reference("/" + unhash).get() == encr_ver_hash:
                messagebox.showinfo("Bootleg Firebase Drive", "Account created successfully!\nYou can log in now.")
            else:
                messagebox.showwarning("Error", "Failed to create an accout!\nPlease, restart the software and try again.")
            form.destroy()
        else:
            messagebox.showwarning("Error", "Passwords don't match.")
    else:
        messagebox.showwarning("Can't create an account", "That username is already taken!\nPlease, choose a different username and try again.")

def derive_key_with_pbkdf2(password, salt, keylen):
    password_bytes = password.encode('utf-8')  # Encode password string to bytes
    salt_bytes = bytes(salt)  # Convert salt list to bytes
    dk = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen=keylen)
    return dk

def get_files_list():
    ref = db.reference('/')
    snapshot = ref.get()
    files_list = []

    if snapshot:
        for key, value in snapshot.items():
            files_list.append(key)

    return files_list

def hash_string(input_string):
    # Convert the input string to bytes
    input_bytes = input_string.encode('utf-8')
    
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the input bytes
    sha256_hash.update(input_bytes)
    
    # Get the hexadecimal digest of the hash
    hex_digest = sha256_hash.hexdigest()
    
    return hex_digest

if __name__ == "__main__":
    db_url_file_name = open("db_url.txt", "r")
    db_url = db_url_file_name.read()
    db_url_file_name.close()
    cred = credentials.Certificate("firebase key.json")
    firebase_admin.initialize_app(cred, {"databaseURL": db_url})
    print(get_files_list())
    #print(db.reference("/1").get())
    sign_in_window()