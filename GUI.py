import tkinter as tk
from tkinter import messagebox
import threading
import subprocess
import os
from datetime import datetime, timedelta
import json

URL_MAPPING = {

    # Вставить название и адрес(без порта) SIEM-системы
    
    "SIEM": "https://1.1.1.1"
}

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("O2 Demo")
        self.geometry("350x400")
        
        self.selected_name = tk.StringVar(self)
        self.selected_name.set(list(URL_MAPPING.keys())[0])
        
        self.show_input_window()

    def update_json_file(self, new_url):
        file_path = "SIEM.json"
        if not os.path.exists(file_path):
            
            # Вставить username в системе
            
            data = [{"name": "NAME", "url": new_url, "user": "USERNAME", "password": "PASSWORD"}]
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data and isinstance(data, list):
                data[0]["url"] = new_url
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def show_input_window(self):
        self.clear_window()
        
        tk.Label(self, text="Выберите сервер:").pack(pady=(10, 0))
        self.menu = tk.OptionMenu(self, self.selected_name, *URL_MAPPING.keys())
        self.menu.pack(pady=5)

        try: cb_uuid = self.clipboard_get()
        except: cb_uuid = ""
        tk.Label(self, text="UUID:").pack(pady=(10, 0))
        self.ent_uuid = tk.Entry(self, width=30)
        self.ent_uuid.insert(0, cb_uuid)
        self.ent_uuid.pack()

        fmt = "%d-%m-%Y %H:%M"
        now = datetime.now()
        yesterday = now - timedelta(hours=24)

        tk.Label(self, text="Time From (ДД-ММ-ГГГГ ЧЧ:ММ):").pack(pady=(10, 0))
        self.ent_from = tk.Entry(self, width=30)
        self.ent_from.insert(0, yesterday.strftime(fmt))
        self.ent_from.pack()

        tk.Label(self, text="Time To (ДД-ММ-ГГГГ ЧЧ:ММ):").pack(pady=(10, 0))
        self.ent_to = tk.Entry(self, width=30)
        self.ent_to.insert(0, now.strftime(fmt))
        self.ent_to.pack()

        tk.Button(self, text="Запустить", command=self.start_process, bg="#e1e1e1").pack(pady=25)

    def start_process(self):
        chosen_name = self.selected_name.get()
        chosen_url = URL_MAPPING[chosen_name]
        
        try:
            self.update_json_file(chosen_url)
        except Exception as e:
            messagebox.showerror("Ошибка JSON", f"Не удалось обновить SIEM.json: {e}")
            return

        args = [self.ent_uuid.get(), self.ent_from.get(), self.ent_to.get(), chosen_url]
        self.show_loading_window()
        threading.Thread(target=self.run_script, args=(args,), daemon=True).start()

    def run_script(self, args):
        try:
            subprocess.run(["python", "script.py"] + args, check=True)
            self.after(0, self.show_final_window)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка: {e}"))
            self.after(0, self.show_input_window)

    def show_loading_window(self):
        self.clear_window()
        tk.Label(self, text="\n\nВыполнение скрипта...", font=("Arial", 12)).pack()
        tk.Label(self, text="Это может занять некоторое время").pack()

    def show_final_window(self):
        self.clear_window()
        tk.Label(self, text="\nГотово!", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Button(self, text="Открыть HTML отчет", command=self.open_html, width=20, height=2).pack(pady=10)
        tk.Button(self, text="Назад", command=self.show_input_window).pack(pady=5)

    def open_html(self):
        file = "process_tree.html"
        if os.path.exists(file):
            os.startfile(file) if os.name == 'nt' else subprocess.run(['open', file])

    def clear_window(self):
        for widget in self.winfo_children(): widget.destroy()

if __name__ == "__main__":
    App().mainloop()
