import random
import string
import tkinter as tk
from tkinter import messagebox

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Password Generator")

        self.length_label = tk.Label(master, text="Password Length: ")
        self.length_label.pack()

        self.length_var = tk.IntVar(value=10)
        self.length_entry = tk.Entry(master, textvariable=self.length_var)
        self.length_entry.pack()

        self.complexity_label = tk.Label(master, text="Select Complexity:")
        self.complexity_label.pack()

        self.complexity_var = tk.StringVar(value="Medium")
        self.complexity_options = ["Low", "Medium", "High"]
        self.complexity_menu = tk.OptionMenu(master, self.complexity_var, *self.complexity_options)
        self.complexity_menu.pack()

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.password_label = tk.Label(master, text="Generated Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(master, width=50)
        self.password_entry.pack()

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack()

    def generate_password(self):
        length = self.length_var.get()
        complexity = self.complexity_var.get()

        if length < 3:
            messagebox.showerror("Error", "Password length must be at least 3.")
            return

        characters = ""
        if complexity == "Low":
            characters = string.ascii_lowercase
        elif complexity == "Medium":
            characters = string.ascii_letters + string.digits
        elif complexity == "High":
            characters = string.ascii_letters + string.digits + string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    password_generator = PasswordGenerator(root)
    root.mainloop()
