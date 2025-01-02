import random
import string
import tkinter as tk
from tkinter import messagebox

def generate_password():
    # Retrieve user inputs
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError("Length must be greater than 0.")
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for length.")
        return

    complexity = complexity_var.get()

    # Define character sets based on complexity level
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = string.punctuation

    if complexity == "Simple":
        char_set = lower
    elif complexity == "Medium":
        char_set = lower + upper + num
    elif complexity == "Hard":
        char_set = lower + upper + num + symbols
    else:
        messagebox.showerror("Invalid Selection", "Please select a complexity level.")
        return

    if length < len(char_set):
        password = "".join(random.sample(char_set, length))
    else:
        password = "".join(random.choices(char_set, k=length))

    password_output.delete(0, tk.END)
    password_output.insert(0, password)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_output.get())
    root.update()  # Update the clipboard
    messagebox.showinfo("Copied", "Password copied to clipboard!")


# GUI Setup
root = tk.Tk()
root.title("Password Generator")
root.geometry("500x300")
root.config(bg="sky blue")
root.resizable(False, False)

# Password Length Input
length_label = tk.Label(root, text="Enter password length:")
length_label.pack(pady=5)

length_entry = tk.Entry(root)
length_entry.pack(pady=5)

# Complexity Level Selection
complexity_label = tk.Label(root, text="Select complexity level:")
complexity_label.pack(pady=5)

complexity_var = tk.StringVar(value="Simple")
complexity_frame = tk.Frame(root)
complexity_frame.pack(pady=5)

simple_button = tk.Radiobutton(complexity_frame, text="Simple", variable=complexity_var, value="Simple")
simple_button.pack(side=tk.LEFT)

medium_button = tk.Radiobutton(complexity_frame, text="Medium", variable=complexity_var, value="Medium")
medium_button.pack(side=tk.LEFT)

hard_button = tk.Radiobutton(complexity_frame, text="Hard", variable=complexity_var, value="Hard")
hard_button.pack(side=tk.LEFT)

# Generate Password Button
generate_button = tk.Button(root, text="Generate Password", command=generate_password)
generate_button.pack(pady=10)

# Password Output
password_output = tk.Entry(root, width=30, font=("Arial", 14), justify="center")
password_output.pack(pady=10)

# Copy to Clipboard Button
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=10)

# Run the application
root.mainloop()