import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import io

START_MARKER = "<!--START-->"
END_MARKER = "<!--END-->"


def text_to_bits(s: str) -> str:
    b = s.encode('utf-8')
    return ''.join(f'{byte:08b}' for byte in b)


def bits_to_text(bstr: str) -> str:
    bytes_out = [int(bstr[i:i + 8], 2) for i in range(0, len(bstr), 8)]
    try:
        return bytes(bytes_out).decode('utf-8', errors='replace')
    except Exception:
        return bytes(bytes_out).decode('utf-8', errors='replace')


def available_capacity(img, channels, lsb):
    w, h = img.size
    used = sum(1 for c in channels.lower() if c in 'rgb')
    return w * h * used * lsb


def hide_message(img, message, channels='rgb', lsb=1):
    if lsb < 1 or lsb > 3:
        raise ValueError("LSB повинен бути від 1 до 3")
    channels = channels.lower()

    full_msg = START_MARKER + message + END_MARKER
    data_bytes = full_msg.encode('utf-8')
    data_bits = ''.join(f'{b:08b}' for b in data_bytes)

    capacity = available_capacity(img, channels, lsb)
    if len(data_bits) > capacity:
        raise ValueError(f"Неможливо вбудувати: потрібно {len(data_bits)} бітів, доступно {capacity} бітів.")

    out_img = img.convert('RGBA') if img.mode in ('RGBA', 'LA') else img.convert('RGB')
    pixels = list(out_img.getdata())
    new_pixels = []
    bit_idx = 0
    channels_map = {'r': 0, 'g': 1, 'b': 2}

    for px in pixels:
        px_list = list(px)
        for ch in channels:
            if ch not in channels_map:
                continue
            idx = channels_map[ch]
            orig_val = px_list[idx]
            for b in range(lsb):
                if bit_idx >= len(data_bits):
                    break
                bit = int(data_bits[bit_idx])
                mask = ~(1 << b)
                new_val = (orig_val & mask) | (bit << b)
                orig_val = new_val
                bit_idx += 1
            px_list[idx] = orig_val
            if bit_idx >= len(data_bits):
                break
        new_pixels.append(tuple(px_list))
        if bit_idx >= len(data_bits):
            break

    out = Image.new(out_img.mode, out_img.size)
    out.putdata(new_pixels + pixels[len(new_pixels):])
    return out, len(data_bits), capacity


def extract_message(img, channels='rgb', lsb=1):
    channels = channels.lower()
    imgc = img.convert('RGB')
    pixels = list(imgc.getdata())
    bits = []
    channels_map = {'r': 0, 'g': 1, 'b': 2}

    for px in pixels:
        for ch in channels:
            if ch not in channels_map:
                continue
            val = px[channels_map[ch]]
            for b in range(lsb):
                bit = (val >> b) & 1
                bits.append(str(bit))
    bitstr = ''.join(bits)

    bytes_list = []
    for i in range(0, len(bitstr), 8):
        byte_bits = bitstr[i:i + 8]
        if len(byte_bits) < 8:
            break
        bytes_list.append(int(byte_bits, 2))

    data = bytes(bytes_list)
    text = data.decode('utf-8', errors='ignore')

    start = text.find(START_MARKER)
    end = text.find(END_MARKER)
    if start != -1 and end != -1 and end > start:
        return text[start + len(START_MARKER):end]
    else:
        raise ValueError("Не знайдено маркерів початку/кінця. Можливо, повідомлення відсутнє.")


def image_file_size(path_or_bytes):
    if isinstance(path_or_bytes, str):
        return os.path.getsize(path_or_bytes)
    else:
        return len(path_or_bytes.getvalue())


class SteganoApp:
    def __init__(self, root):
        self.root = root
        root.title("Приховування тексту в зображенні")
        self.image = None
        self.stego_image = None
        self.hidden_bits = 0
        self.capacity = 0

        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        self.canvas = tk.Canvas(frm, width=400, height=300, bg='grey')
        self.canvas.grid(row=0, column=0, rowspan=8, padx=(0, 10))

        ttk.Button(frm, text="Завантажити зображення", command=self.load_image).grid(row=0, column=1, sticky="ew")
        ttk.Button(frm, text="Зберегти стего-зображення", command=self.save_stego).grid(row=1, column=1, sticky="ew")

        ttk.Label(frm, text="Повідомлення:").grid(row=2, column=1, sticky="w")
        self.msg_text = tk.Text(frm, height=6, width=40)
        self.msg_text.grid(row=3, column=1, sticky="ew")

        opts = ttk.Frame(frm)
        opts.grid(row=4, column=1, sticky="ew")
        ttk.Label(opts, text="Канали:").grid(row=0, column=0, sticky="w")
        self.channels_var = tk.StringVar(value="rgb")
        ttk.Entry(opts, textvariable=self.channels_var, width=6).grid(row=0, column=1, sticky="w")
        ttk.Label(opts, text="LSB:").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.lsb_var = tk.IntVar(value=1)
        ttk.Spinbox(opts, from_=1, to=3, textvariable=self.lsb_var, width=4).grid(row=0, column=3, sticky="w")

        ttk.Button(frm, text="Приховати повідомлення", command=self.on_hide).grid(row=5, column=1, sticky="ew")
        ttk.Separator(frm, orient='horizontal').grid(row=6, column=0, columnspan=2, sticky="ew", pady=6)

        button_frame = ttk.Frame(frm)
        button_frame.grid(row=7, column=0, columnspan=2, sticky="ew")
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        ttk.Button(button_frame, text="Витягнути повідомлення", command=self.on_extract).grid(row=0, column=0,
                                                                                              sticky="ew", padx=(0, 5))
        ttk.Button(button_frame, text="Аналізувати зображення", command=self.on_analyze).grid(row=0, column=1,
                                                                                              sticky="ew", padx=(5, 0))

        self.status = ttk.Label(frm, text="Зображення не завантажено", foreground="blue")
        self.status.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

    def load_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Зображення", "*.png;*.bmp;*.jpg;*.jpeg;*.tiff"), ("Всі файли", "*.*")])
        if not path:
            return
        img = Image.open(path)
        self.image_path = path
        self.image = img.copy()
        self.show_image(self.image)
        self.status.config(text=f"Завантажено: {os.path.basename(path)}")
        self.stego_image = None

    def show_image(self, img):
        w, h = img.size
        max_w, max_h = 400, 300
        scale = min(max_w / w, max_h / h, 1.0)
        new_w = int(w * scale)
        new_h = int(h * scale)
        disp = img.resize((new_w, new_h), Image.LANCZOS)
        self.tkimg = ImageTk.PhotoImage(disp)
        self.canvas.delete("all")
        self.canvas.create_image(200, 150, image=self.tkimg)

    def save_stego(self):
        if self.stego_image is None:
            messagebox.showwarning("Немає стего", "Спочатку приховайте повідомлення.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png"), ("BMP", "*.bmp")])
        if not path:
            return
        self.stego_image.save(path)
        self.status.config(text=f"Збережено: {os.path.basename(path)}")
        messagebox.showinfo("Збережено", "Стего-зображення збережено.")

    def on_hide(self):
        if self.image is None:
            messagebox.showwarning("Немає зображення", "Завантажте зображення.")
            return
        message = self.msg_text.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("Немає повідомлення", "Введіть повідомлення.")
            return
        channels = self.channels_var.get().strip().lower() or 'rgb'
        lsb = int(self.lsb_var.get())
        try:
            stego, hidden_bits, capacity = hide_message(self.image, message, channels=channels, lsb=lsb)
            self.stego_image = stego
            self.hidden_bits = hidden_bits
            self.capacity = capacity
            self.show_image(stego)
            self.status.config(text="Повідомлення приховано ✔")
            messagebox.showinfo("Успіх", "Повідомлення успішно приховано.")
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def on_extract(self):
        if self.image is None:
            messagebox.showwarning("Немає зображення", "Завантажте зображення.")
            return
        channels = self.channels_var.get().strip().lower() or 'rgb'
        lsb = int(self.lsb_var.get())
        try:
            found = extract_message(self.image, channels=channels, lsb=lsb)
            dlg = tk.Toplevel(self.root)
            dlg.title("Витягнуте повідомлення")
            txt = tk.Text(dlg, wrap='word', width=60, height=20)
            txt.pack(padx=10, pady=10)
            txt.insert("1.0", found)
            txt.configure(state='disabled')
            messagebox.showinfo("Успіх", "Повідомлення витягнуто.")
        except Exception as e:
            messagebox.showerror("Помилка витягнення", str(e))

    def on_analyze(self):
        if self.image is None or self.stego_image is None:
            messagebox.showwarning("Потрібні обидва зображення",
                                   "Завантажте оригінальне та стего-зображення перед аналізом.")
            return

        try:
            # розмір оригіналу
            orig_size = os.path.getsize(self.image_path) if hasattr(self, 'image_path') else None

            # розмір стего-зображення
            bio = io.BytesIO()
            self.stego_image.save(bio, format='PNG')
            stego_size = len(bio.getvalue())

            # обчислення різниці в межах 0–100%
            diff_percent = (abs(stego_size - orig_size) / max(stego_size, orig_size)) * 100 if orig_size else 0

            info = (
                f"Аналіз змін у зображенні:\n\n"
                f"Розмір оригіналу: {orig_size} байт\n"
                f"Розмір стего-зображення: {stego_size} байт\n"
                f"Розмір зображення збільшився на: {diff_percent:.2f}%"
            )

            messagebox.showinfo("Аналіз зображень", info)

        except Exception as e:
            messagebox.showerror("Помилка аналізу", str(e))
def main():
    root = tk.Tk()
    app = SteganoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
