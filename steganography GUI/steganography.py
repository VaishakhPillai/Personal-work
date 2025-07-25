import cv2
import numpy as np
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk


# Generate a key for encryption/decryption
def generate_key():
    return Fernet.generate_key()


# Encrypt the message
def encrypt_message(key, message):
    cipher = Fernet(key)
    return cipher.encrypt(message.encode())


# Decrypt the message
def decrypt_message(key, encrypted_message):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_message).decode()


# Convert message to binary
def message_to_binary(message):
    return "".join(format(byte, "08b") for byte in message)


# Convert binary to message
def binary_to_message(binary_string):
    bytes_list = [binary_string[i : i + 8] for i in range(0, len(binary_string), 8)]
    return bytes([int(byte, 2) for byte in bytes_list])


# Embed data using LSB
def embed_data(image, data):
    binary_data = message_to_binary(data)
    data_len = len(binary_data)
    img_flat = image.flatten()

    if data_len > len(img_flat):
        raise ValueError("Data too large to fit in the image")

    for i in range(data_len):
        img_flat[i] = (img_flat[i] & 0xFE) | int(binary_data[i])

    return img_flat.reshape(image.shape)


# Extract data using LSB
def extract_data(image, length):
    img_flat = image.flatten()
    binary_data = "".join(str(img_flat[i] & 1) for i in range(length * 8))
    return binary_to_message(binary_data)


# GUI Application
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Data Hiding")
        self.image_path = ""
        self.key = generate_key()

        # UI Elements
        tk.Label(root, text="Message to Hide:").pack()
        self.message_text = ScrolledText(root, height=5)
        self.message_text.pack(padx=10, pady=5)

        tk.Button(root, text="Choose Image", command=self.load_image).pack(pady=5)
        tk.Button(root, text="Embed & Save Image", command=self.embed_and_save).pack(
            pady=5
        )
        tk.Button(root, text="Extract Message", command=self.extract_message).pack(
            pady=5
        )

        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=5)

    def load_image(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg")]
        )
        if self.image_path:
            self.status_label.config(text=f"Loaded image: {self.image_path}")

    def embed_and_save(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected")
            return
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "No message entered")
            return

        image = cv2.imread(self.image_path)
        encrypted_message = encrypt_message(self.key, message)
        stego_image = embed_data(image, encrypted_message)
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png", filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            cv2.imwrite(save_path, stego_image)
            self.status_label.config(text="Image saved with hidden message.")
            messagebox.showinfo("Success", "Message embedded and image saved!")

    def extract_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected")
            return

        image = cv2.imread(self.image_path)
        try:
            # Estimating length of message: assuming user knows or testing max 300 chars
            extracted_data = extract_data(image, 300)
            decrypted_message = decrypt_message(self.key, extracted_data)
            messagebox.showinfo("Hidden Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract message: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
