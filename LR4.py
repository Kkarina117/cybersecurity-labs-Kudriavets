import hashlib
from pathlib import Path
import json

MODULO = 1_000_003
SALT = "UniqueSalt_2024"

def compute_file_hash(path: str) -> int:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Файл '{path}' не знайдено.")
    data = file_path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    return int(sha, 16) % MODULO

# Генерація ключів
def generate_keys(name: str, dob: str, secret: str) -> tuple[int, int]:
    base = (name + dob + secret + SALT).encode("utf-8")
    md5 = hashlib.md5(base).hexdigest()
    private_key = int(md5, 16) % MODULO
    public_key = (private_key * 11 + 7) % MODULO
    return private_key, public_key

# Створення цифрового підпису
def create_signature(file_path: str, private_key: int) -> int:
    h = compute_file_hash(file_path)
    signature = (h + private_key * 3) % MODULO
    return signature

# Перевірка підпису
def verify_signature(file_path: str, signature: int, public_key: int) -> bool:
    inv_11 = pow(11, -1, MODULO)
    approx_private = ((public_key - 7) * inv_11) % MODULO
    h = compute_file_hash(file_path)
    expected_signature = (h + approx_private * 3) % MODULO
    return expected_signature == signature

#  Збереження підпису
def save_signature(path: str, signature: int, public_key: int):
    data = {
        "file": path,
        "signature": signature,
        "public_key": public_key
    }
    Path("signature.json").write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print("Підпис збережено у файл signature.json")

#  Читання підпису
def load_signature():
    if not Path("signature.json").exists():
        print("Файл signature.json не знайдено.")
        return None
    return json.loads(Path("signature.json").read_text())


#  Створення підробленої версії файлу
def create_tampered_copy(path: str) -> str:
    orig = Path(path).read_bytes()
    tampered_path = "tampered_" + Path(path).name
    addon = "\n(ЗМІНЕНО ДЛЯ ДЕМОНСТРАЦІЇ)".encode("utf-8")
    Path(tampered_path).write_bytes(orig + addon)
    return tampered_path

# Меню

def main_menu():
    private_key = None
    public_key = None
    signature = None
    path = None

    while True:
        print("\n===== МЕНЮ СИСТЕМИ ЦИФРОВОГО ПІДПИСУ =====")
        print("1 — Генерація ключів")
        print("2 — Створити цифровий підпис")
        print("3 — Зберегти підпис у файл")
        print("4 — Завантажити підпис з файлу")
        print("5 — Перевірити підпис")
        print("6 — Демонстрація підробки")
        print("0 — Вихід")

        choice = input("Ваш вибір: ")

        # 1 — Генерація ключів
        if choice == "1":
            name = input("Введіть ім'я: ")
            dob = input("Дата народження (ДДММРРРР): ")
            secret = input("Секретне слово: ")
            private_key, public_key = generate_keys(name, dob, secret)
            print("\nПриватний ключ:", private_key)
            print("Публічний ключ:", public_key)

        # 2 — Створення підпису
        elif choice == "2":
            if private_key is None:
                print("Спочатку згенеруйте ключі!")
                continue
            path = input("Шлях до файлу: ")
            try:
                signature = create_signature(path, private_key)
                print("Підпис створено:", signature)
            except FileNotFoundError as e:
                print(e)

        # 3 — Збереження підпису
        elif choice == "3":
            if signature is None or path is None:
                print("Спочатку створіть підпис!")
                continue
            save_signature(path, signature, public_key)

        # 4 — Завантаження підпису
        elif choice == "4":
            data = load_signature()
            if data:
                signature = data["signature"]
                public_key = data["public_key"]
                path = data["file"]
                print("Підпис та ключ завантажені.")

        # 5 — Перевірка підпису
        elif choice == "5":
            if public_key is None or path is None or signature is None:
                print("Спочатку згенеруйте ключі або завантажте підпис!")
                continue
            try:
                ok = verify_signature(path, signature, public_key)
                print("\nРЕЗУЛЬТАТ:", "ПІДПИС ДІЙСНИЙ" if ok else "ПІДРОБЛЕНИЙ")
            except FileNotFoundError as e:
                print(e)

        # 6 — Демонстрація підробки
        elif choice == "6":
            if path is None or signature is None or public_key is None:
                print("Спочатку створіть або завантажте підпис!")
                continue
            try:
                tampered = create_tampered_copy(path)
                print("Створено змінену копію:", tampered)
                ok = verify_signature(tampered, signature, public_key)
                print("Перевірка підробки:", "ПІДПИС ДІЙСНИЙ" if ok else "ПІДРОБЛЕНИЙ")
            except FileNotFoundError as e:
                print(e)

        elif choice == "0":
            break
        else:
            print("Невідомий пункт меню!")

if __name__ == "__main__":
    main_menu()
