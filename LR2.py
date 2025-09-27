import tkinter as tk
from tkinter import ttk, messagebox
import collections

# Графік
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Український алфавіт у звичайному порядку
UKR_ALPHABET_LOWER = [
    'а', 'б', 'в', 'г', 'ґ', 'д', 'е', 'є', 'ж', 'з', 'и', 'і', 'ї', 'й', 'к', 'л', 'м', 'н', 'о', 'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ь', 'ю', 'я'
]
UKR_ALPHABET_UPPER = [c.upper() for c in UKR_ALPHABET_LOWER]
ALPHABET_LEN = len(UKR_ALPHABET_LOWER)  # 33


def is_ukr_letter(ch):
    return ch in UKR_ALPHABET_LOWER or ch in UKR_ALPHABET_UPPER

def letter_index(ch):
    if ch in UKR_ALPHABET_LOWER:
        return UKR_ALPHABET_LOWER.index(ch)
    if ch in UKR_ALPHABET_UPPER:
        return UKR_ALPHABET_UPPER.index(ch)
    return None

def shift_letter(ch, shift):
    idx = letter_index(ch)
    if idx is None:
        return ch
    if ch.isupper():
        return UKR_ALPHABET_UPPER[(idx + shift) % ALPHABET_LEN]
    else:
        return UKR_ALPHABET_LOWER[(idx + shift) % ALPHABET_LEN]


# Шифр Цезаря
def caesar_encrypt(text, shift):
    return ''.join(shift_letter(ch, shift) for ch in text)

def caesar_decrypt(text, shift):
    return ''.join(shift_letter(ch, -shift) for ch in text)


# Шифр Віженера
def normalize_key_to_shifts(key):
    shifts = []
    for ch in key:
        idx = letter_index(ch)
        if idx is not None:
            shifts.append(idx)
    return shifts

def vigenere_encrypt(text, key):
    shifts = normalize_key_to_shifts(key)
    if not shifts:
        messagebox.showwarning('Попередження', 'Ключ Віженера не містить українських літер. Текст не змінено.')
        return text
    out = []
    k = 0
    for ch in text:
        idx = letter_index(ch)
        if idx is None:
            out.append(ch)
            continue
        shift = shifts[k % len(shifts)]
        out.append(shift_letter(ch, shift))
        k += 1
    return ''.join(out)


def vigenere_decrypt(text, key):
    shifts = normalize_key_to_shifts(key)
    if not shifts:
        messagebox.showwarning('Попередження', 'Ключ Віженера не містить українських літер. Текст не змінено.')
        return text
    out = []
    k = 0
    for ch in text:
        idx = letter_index(ch)
        if idx is None:
            out.append(ch)
            continue
        shift = shifts[k % len(shifts)]
        out.append(shift_letter(ch, -shift))
        k += 1
    return ''.join(out)


# Метрики та аналіз
def fraction_ukr_letters(text):
    if not text:
        return 0.0
    letters = sum(1 for ch in text if is_ukr_letter(ch))
    return letters / len(text)


def key_complexity_caesar(shift):
    return ALPHABET_LEN


def key_complexity_vigenere(key):
    klen = len(normalize_key_to_shifts(key))
    if klen == 0:
        return 0
    return ALPHABET_LEN ** klen


# Частотний аналіз
def letter_frequencies(text):
    text_letters = [ch.lower() for ch in text if is_ukr_letter(ch)]
    counts = collections.Counter(text_letters)
    freqs = {ch: counts.get(ch, 0) for ch in UKR_ALPHABET_LOWER}
    return freqs


class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Порівняльний аналіз шифрів (Цезарь і Віженер)')
        self.geometry('1000x700')

        self.caesar_shift = 8
        self.vigenere_key = 'Кудрявець'

        self.txt_input = None
        self.spin_shift = None
        self.entry_vig_key = None
        self.txt_caesar = None
        self.txt_vig = None
        self.tree = None

        self.create_widgets()

    def create_widgets(self):
        frm_top = ttk.Frame(self)
        frm_top.pack(fill='x', padx=8, pady=6)

        ttk.Label(frm_top, text='Вхідний текст:').grid(row=0, column=0, sticky='w')
        self.txt_input = tk.Text(frm_top, height=6)
        self.txt_input.grid(row=1, column=0, columnspan=4, sticky='we', padx=4, pady=4)
        self.txt_input.insert('1.0', 'Захист інформації – важлива дисципліна')

        # Ключі
        ttk.Label(frm_top, text='Цезарь — зсув (число):').grid(row=2, column=0, sticky='w')
        self.spin_shift = tk.Spinbox(frm_top, from_=-100, to=100, width=6)
        self.spin_shift.delete(0, 'end')
        self.spin_shift.insert(0, str(self.caesar_shift))
        self.spin_shift.grid(row=2, column=1, sticky='w')

        ttk.Label(frm_top, text='Віженер — ключ (прізвище):').grid(row=2, column=2, sticky='w')
        self.entry_vig_key = ttk.Entry(frm_top, width=20)
        self.entry_vig_key.insert(0, self.vigenere_key)
        self.entry_vig_key.grid(row=2, column=3, sticky='w')

        # Панель вивідних текстів
        frm_out = ttk.Frame(self)
        frm_out.pack(fill='both', expand=True, padx=8, pady=6)

        # Вивід для Цезаря
        left = ttk.LabelFrame(frm_out, text='Результат (Цезарь)')
        left.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        self.txt_caesar = tk.Text(left, height=15)
        self.txt_caesar.pack(fill='both', expand=True, padx=4, pady=4)

        # Кнопки для Цезаря під полем
        caesar_btn_frame = ttk.Frame(left)
        caesar_btn_frame.pack(fill='x', padx=4, pady=4)
        ttk.Button(caesar_btn_frame, text='Шифрувати (Цезарь)', command=self.encrypt_caesar).pack(side='left', padx=4)
        ttk.Button(caesar_btn_frame, text='Розшифрувати (Цезарь)', command=self.decrypt_caesar).pack(side='left',
                                                                                                     padx=4)

        # Вивід для Віженера
        right = ttk.LabelFrame(frm_out, text='Результат (Віженер)')
        right.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        self.txt_vig = tk.Text(right, height=15)
        self.txt_vig.pack(fill='both', expand=True, padx=4, pady=4)

        # Кнопки для Віженера під полем
        vigenere_btn_frame = ttk.Frame(right)
        vigenere_btn_frame.pack(fill='x', padx=4, pady=4)
        ttk.Button(vigenere_btn_frame, text='Шифрувати (Віженер)', command=self.encrypt_vigenere).pack(side='left',
                                                                                                       padx=4)
        ttk.Button(vigenere_btn_frame, text='Розшифрувати (Віженер)', command=self.decrypt_vigenere).pack(side='left',
                                                                                                          padx=4)
        # Загальні кнопки
        general_btn_frame = ttk.Frame(self)
        general_btn_frame.pack(fill='x', padx=8, pady=4)
        ttk.Button(general_btn_frame, text='Частотний аналіз (графік)', command=self.show_frequency_plot).pack(
            side='left', padx=12)
        ttk.Button(general_btn_frame, text='Порівняти результати', command=self.compare_results).pack(side='left',
                                                                                                      padx=12)

        # Таблиця порівнянь
        bottom = ttk.LabelFrame(self, text='Таблиця порівнянь')
        bottom.pack(fill='x', padx=8, pady=6)

        cols = ('method', 'length', 'readability', 'key_complexity')
        col_names = {'method': 'Метод', 'length': 'Довжина результату', 'readability': 'Читабельність', 'key_complexity': 'Складність ключа'}
        self.tree = ttk.Treeview(bottom, columns=cols, show='headings', height=3)
        for c in cols:
            self.tree.heading(c, text=col_names.get(c, c))
            self.tree.column(c, width=200, anchor='center')
        self.tree.pack(fill='x')

    def get_input_text(self):
        return self.txt_input.get('1.0', 'end').rstrip('\n')

    def encrypt_caesar(self):
        text = self.get_input_text()
        try:
            shift = int(self.spin_shift.get())
        except ValueError:
            messagebox.showerror('Помилка', 'Зсув повинен бути числом')
            return
        res = caesar_encrypt(text, shift)
        self.txt_caesar.delete('1.0', 'end')
        self.txt_caesar.insert('1.0', res)

    def decrypt_caesar(self):
        text = self.get_input_text()
        try:
            shift = int(self.spin_shift.get())
        except ValueError:
            messagebox.showerror('Помилка', 'Зсув повинен бути числом')
            return
        res = caesar_decrypt(text, shift)
        self.txt_caesar.delete('1.0', 'end')
        self.txt_caesar.insert('1.0', res)

    def encrypt_vigenere(self):
        text = self.get_input_text()
        key = self.entry_vig_key.get()
        res = vigenere_encrypt(text, key)
        self.txt_vig.delete('1.0', 'end')
        self.txt_vig.insert('1.0', res)

    def decrypt_vigenere(self):
        text = self.get_input_text()
        key = self.entry_vig_key.get()
        res = vigenere_decrypt(text, key)
        self.txt_vig.delete('1.0', 'end')
        self.txt_vig.insert('1.0', res)

    def show_frequency_plot(self):
        text = self.get_input_text()
        freqs = letter_frequencies(text)
        labels = UKR_ALPHABET_LOWER
        values = [freqs.get(l, 0) for l in labels]

        if not MATPLOTLIB_AVAILABLE:
            messagebox.showwarning('Бібліотека відсутня', 'matplotlib не встановлений. Встановіть matplotlib, щоб бачити графіки.')
            return

        win = tk.Toplevel(self)
        win.title('Частотний аналіз')
        fig = Figure(figsize=(10, 4))
        ax = fig.add_subplot(111)
        ax.bar(labels, values)
        ax.set_title('Частота літер (тільки українські літери)')
        ax.set_xlabel('Літера')
        ax.set_ylabel('Кількість')
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def compare_results(self):
        original = self.get_input_text()
        caesar_text = self.txt_caesar.get('1.0', 'end').rstrip('\n')
        vig_text = self.txt_vig.get('1.0', 'end').rstrip('\n')

        if not caesar_text:
            try:
                shift = int(self.spin_shift.get())
            except ValueError:
                shift = self.caesar_shift
            caesar_text = caesar_encrypt(original, shift)

        if not vig_text:
            key = self.entry_vig_key.get()
            vig_text = vigenere_encrypt(original, key)

        # Очищення таблиці
        for i in self.tree.get_children():
            self.tree.delete(i)

        # Обчислення показників
        rows = []
        for name, txt, key_info in (
            ('Caesar', caesar_text, ('shift', int(self.spin_shift.get()) if self.spin_shift.get().lstrip('-').isdigit() else self.caesar_shift)),
            ('Vigenere', vig_text, ('key', self.entry_vig_key.get()))
        ):
            length = len(txt)
            frac = fraction_ukr_letters(txt)
            if frac > 0.9:
                readability = 'Висока'
            elif frac > 0.7:
                readability = 'Середня'
            else:
                readability = 'Низька'
            if name == 'Caesar':
                key_complex_level = 'Низька'
            else:
                klen = len(normalize_key_to_shifts(key_info[1]))
                if klen < 3:
                    key_complex_level = 'Низька'
                elif klen < 6:
                    key_complex_level = 'Середня'
                else:
                    key_complex_level = 'Висока'
            rows.append((name, str(length), readability, key_complex_level))

        # Додавання рядків до таблиці
        for r in rows:
            self.tree.insert('', 'end', values=r)

if __name__ == '__main__':
    app = CipherApp()
    app.mainloop()
