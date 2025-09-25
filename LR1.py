import tkinter as tk
from tkinter import scrolledtext
import re

def analyze_password():
    password = entry_password.get()
    name = entry_name.get().lower()
    dob = entry_dob.get()  # формат дд.мм.рррр

    score = 0
    recommendations = []
    personal_data_issues = []

    # Валідація дати народження
    if dob and not re.match(r'\d{2}\.\d{2}\.\d{4}', dob):
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Помилка: Некоректний формат дати (дд.мм.рррр).")
        result_text.config(fg="red")
        return
    day, month, year = dob.split('.') if dob else ('', '', '')

    # Перевірка персональних даних
    if name and name in password.lower():
        personal_data_issues.append(f"Пароль містить ім'я '{name}'")
    if year and year in password:
        personal_data_issues.append(f"Пароль містить рік народження '{year}'")
    if day and day in password:
        personal_data_issues.append(f"Пароль містить день народження '{day}'")
    if month and month in password:
        personal_data_issues.append(f"Пароль містить місяць народження '{month}'")

    # Оцінка складності пароля
    if len(password) >= 8:
        score += 2
    else:
        recommendations.append("Зробіть пароль довшим за 8 символів.")
    if len(password) >= 12:
        score += 2

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        recommendations.append("Додайте великі літери.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        recommendations.append("Додайте малі літери.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        recommendations.append("Додайте цифри.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        recommendations.append("Додайте спеціальні символи.")

    if not personal_data_issues:
        score += 1
    else:
        recommendations.append("Уникайте використання особистих даних у паролі.")

    score = max(1, min(10, score))  # обмежуємо від 1 до 10

    # Формування результатів
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Оцінка безпеки: {score}/10\n\n")
    result_text.insert(tk.END, "Аналіз:\n")
    if personal_data_issues:
        result_text.insert(tk.END, "- " + "\n- ".join(personal_data_issues) + "\n")
    else:
        result_text.insert(tk.END, "- Немає зв'язку з особистими даними.\n")

    result_text.insert(tk.END, "\nРекомендації:\n")
    if recommendations:
        result_text.insert(tk.END, "- " + "\n- ".join(recommendations))
    else:
        if score >= 8:
            result_text.insert(tk.END, "- Пароль виглядає сильним.")
        else:
            result_text.insert(tk.END, "- Пароль середньої надійності.")

    # Колір
    if score >= 8:
        result_text.config(fg="green")
    elif score >= 5:
        result_text.config(fg="orange")
    else:
        result_text.config(fg="red")

def test_example():
    entry_password.delete(0, tk.END)
    entry_name.delete(0, tk.END)
    entry_dob.delete(0, tk.END)
    entry_password.insert(0, "ivan1995")
    entry_name.insert(0, "Іван")
    entry_dob.insert(0, "15.03.1995")
    analyze_password()


root = tk.Tk()
root.title("Аналіз безпеки паролів")
root.geometry("500x470")
root.configure(bg="#f0f2f5")
root.resizable(False, False)

padx = 10
pady = 8
label_font = ("Arial", 11)
entry_font = ("Arial", 11)
button_font = ("Arial", 11, "bold")
result_font = ("Arial", 11)

tk.Label(root, text="Пароль:", anchor="w", bg="#f0f2f5", font=label_font).grid(row=0, column=0, sticky="w", padx=padx, pady=pady)
tk.Label(root, text="Ім'я:", anchor="w", bg="#f0f2f5", font=label_font).grid(row=1, column=0, sticky="w", padx=padx, pady=pady)
tk.Label(root, text="Дата народження (дд.мм.рррр):", anchor="w", bg="#f0f2f5", font=label_font).grid(row=2, column=0, sticky="w", padx=padx, pady=pady)

entry_password = tk.Entry(root, show="*", font=entry_font, width=25)
entry_name = tk.Entry(root, font=entry_font, width=25)
entry_dob = tk.Entry(root, font=entry_font, width=25)

entry_password.grid(row=0, column=1, padx=padx, pady=pady)
entry_name.grid(row=1, column=1, padx=padx, pady=pady)
entry_dob.grid(row=2, column=1, padx=padx, pady=pady)

tk.Button(root, text="Аналізувати", command=analyze_password, bg="#4CAF50", fg="white", font=button_font).grid(row=3, column=0, padx=padx, pady=10)
tk.Button(root, text="Тестовий приклад", command=test_example, bg="#2196F3", fg="white", font=button_font).grid(row=3, column=1, padx=padx, pady=10)

result_text = scrolledtext.ScrolledText(root, width=55, height=15, wrap=tk.WORD, font=result_font, bg="#ffffff")
result_text.grid(row=4, column=0, columnspan=2, padx=padx, pady=pady)

root.mainloop()

