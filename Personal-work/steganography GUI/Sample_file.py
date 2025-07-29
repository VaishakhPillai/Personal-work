import cv2
import numpy as np
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import hashlib

# === Utility Functions ===


def generate_key():
    return Fernet.generate_key()


def encrypt_message(key, message, level):
    cipher = Fernet(key)
    encrypted = message.encode()
    for _ in range(level):
        encrypted = cipher.encrypt(encrypted)
    return encrypted


def decrypt_message(key, encrypted_message, level):
    cipher = Fernet(key)
    decrypted = encrypted_message
    for _ in range(level):
        decrypted = cipher.decrypt(decrypted)
    return decrypted.decode()


def message_to_binary(message):
    return "".join(format(byte, "08b") for byte in message)


def binary_to_message(binary_string):
    bytes_list = [binary_string[i : i + 8] for i in range(0, len(binary_string), 8)]
    return bytes([int(byte, 2) for byte in bytes_list])


def embed_data(image, data):
    binary_data = message_to_binary(data)
    data_len = len(binary_data)
    img_flat = image.flatten()

    if data_len > len(img_flat):
        raise ValueError("Data too large to fit in the image")

    for i in range(data_len):
        img_flat[i] = (img_flat[i] & 0xFE) | int(binary_data[i])

    return img_flat.reshape(image.shape)


def extract_data(image, length):
    img_flat = image.flatten()
    binary_data = "".join(str(img_flat[i] & 1) for i in range(length * 8))
    return binary_to_message(binary_data)


# === GUI Application ===


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Data Hiding")
        self.image_path = ""
        self.key = generate_key()

        # Message input
        tk.Label(root, text="Message to Hide:").pack()
        self.message_text = ScrolledText(root, height=5)
        self.message_text.pack(padx=10, pady=5)

        # Encryption type (placeholder for extensibility)
        tk.Label(root, text="Encryption Type:").pack()
        self.encryption_var = tk.StringVar(value="Fernet")
        self.encryption_menu = tk.OptionMenu(root, self.encryption_var, "Fernet")
        self.encryption_menu.pack()

        # Confidentiality Level
        tk.Label(root, text="Confidentiality Level (1-5):").pack()
        self.conf_level = tk.IntVar(value=1)
        self.conf_slider = tk.Scale(
            root, from_=1, to=5, orient=tk.HORIZONTAL, variable=self.conf_level
        )
        self.conf_slider.pack()

        # Buttons
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

        level = self.conf_level.get()
        image = cv2.imread(self.image_path)

        try:
            encrypted_message = encrypt_message(self.key, message, level)
            stego_image = embed_data(image, encrypted_message)
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png", filetypes=[("PNG files", "*.png")]
            )

            if save_path:
                # Save stego image
                cv2.imwrite(save_path, stego_image)

                # Save key
                key_path = save_path + ".key"
                with open(key_path, "wb") as f:
                    f.write(self.key)

                self.status_label.config(text="Image and key saved.")
                messagebox.showinfo(
                    "Success",
                    f"Message embedded and image saved!\nKey saved as:\n{key_path}",
                )

        except Exception as e:
            messagebox.showerror("Error", f"Embedding failed: {e}")

    def extract_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected")
            return

        level = self.conf_level.get()
        image = cv2.imread(self.image_path)

        key_path = filedialog.askopenfilename(
            title="Select Key File", filetypes=[("Key Files", "*.key")]
        )
        if not key_path:
            messagebox.showerror("Error", "Key file not selected")
            return

        try:
            with open(key_path, "rb") as f:
                key = f.read()

            extracted_data = extract_data(image, 300)
            decrypted_message = decrypt_message(key, extracted_data, level)
            messagebox.showinfo("Hidden Message", decrypted_message)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract message: {e}")


# === Main Execution ===

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
