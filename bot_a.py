import tkinter as tk
from tkinter import ttk, messagebox
import socket
import requests
import nmap
import subprocess
from prettytable import PrettyTable
import pandas as pd  # Импортируем библиотеку для работы с данными
from sklearn.model_selection import train_test_split  # Импортируем функцию для разделения данных на обучающие и тестовые наборы
from sklearn.ensemble import RandomForestClassifier  # Импортируем алгоритм случайного леса для классификации
from sklearn.metrics import classification_report  # Импортируем функцию для создания отчета о классификации

# Функция для обновления индикатора прогресса и текста
def update_progress(progress_bar, progress_label, value):
    progress_bar['value'] = value
    progress_label['text'] = f"Загрузка: {value}%"
    root.update_idletasks()

# Функция для сканирования портов
def port_scan(host, ports, progress_bar, progress_label):
    open_ports = []
    total_ports = len(ports)
    for i, port in enumerate(ports):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
        update_progress(progress_bar, progress_label, int((i + 1) / total_ports * 100))
    return open_ports

# Функция для проверки доступности IP-адреса
def check_ip(ip, progress_bar, progress_label):
    try:
        socket.gethostbyaddr(ip)
        update_progress(progress_bar, progress_label, 100)
        return True
    except socket.herror:
        update_progress(progress_bar, progress_label, 100)
        return False

# Функция для анализа веб-сайта
def analyze_website(url, progress_bar, progress_label):
    response = requests.get(url)
    update_progress(progress_bar, progress_label, 100)
    return response.headers

# Функция для использования Nmap для сканирования уязвимостей
def nmap_scan(host, progress_bar, progress_label):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-Pn --script vuln')
    update_progress(progress_bar, progress_label, 100)
    
    # Создаем таблицу для вывода результатов
    table = PrettyTable()
    table.field_names = ["Host", "Protocol", "Port", "Name", "State", "Reason"]
    
    for proto in nm[host].all_protocols():
        lport = nm[host][proto].keys()
        for port in lport:
            table.add_row([host, proto, port, nm[host][proto][port]['name'], nm[host][proto][port]['state'], nm[host][proto][port]['reason']])
    
    return table

# Функция для использования OpenVAS
def openvas_scan(host, progress_bar, progress_label):
    command = f"openvas -q -h {host}"
    result = subprocess.getoutput(command)
    update_progress(progress_bar, progress_label, 100)
    return result

# Функция для обучения модели и предсказания уязвимостей
def train_and_predict_vulnerabilities(data_file):
    data = pd.read_csv(data_file)  # Чтение данных из CSV-файла
    X = data[['Port', 'Open']]  # Выбор признаков для обучения
    y = data['Vulnerable']  # Целевая переменная
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)  # Разделение данных на обучающие и тестовые наборы
    model = RandomForestClassifier(n_estimators=100, random_state=42)  # Создание модели случайного леса
    model.fit(X_train, y_train)  # Обучение модели
    y_pred = model.predict(X_test)  # Предсказание на тестовых данных
    report = classification_report(y_test, y_pred)  # Создание отчета о классификации
    print(report)  # Вывод отчета на экран
    messagebox.showinfo("Результат", f"Отчет о классификации:\n{report}")  # Уведомление об успешном обучении модели
    return model  # Возврат обученной модели

# Функция для предсказания уязвимостей на новых данных
def predict_vulnerabilities(model, new_data):
    predictions = model.predict(new_data)  # Предсказание уязвимостей на новых данных
    return predictions  # Возврат предсказаний

# Функция для обработки команд
def execute_command():
    command = command_entry.get().strip().split()
    
    try:
        if len(command) < 3:
            raise ValueError("Недостаточно аргументов для выполнения команды.")
        
        if command[0] == 'scan' and command[1] == 'ports':
            if len(command) != 4:
                raise ValueError("Команда 'scan ports' требует 3 аргумента: [IP] [порты].")
            host = command[2]
            ports = command[3].split(',')
            ports = [int(p) for p in ports]
            progress_bar['value'] = 0
            open_ports = port_scan(host, ports, progress_bar, progress_label)
            messagebox.showinfo("Результат", f'Открытые порты для {host}: {open_ports}')
        
        elif command[0] == 'check' and command[1] == 'ip':
            if len(command) != 3:
                raise ValueError("Команда 'check ip' требует 1 аргумент: [IP].")
            ip = command[2]
            progress_bar['value'] = 0
            if check_ip(ip, progress_bar, progress_label):
                messagebox.showinfo("Результат", f'IP {ip} доступен.')
            else:
                messagebox.showinfo("Результат", f'IP {ip} недоступен.')
        
        elif command[0] == 'analyze' and command[1] == 'website':
            if len(command) != 3:
                raise ValueError("Команда 'analyze website' требует 1 аргумент: [URL].")
            url = command[2]
            progress_bar['value'] = 0
            headers = analyze_website(url, progress_bar, progress_label)
            messagebox.showinfo("Результат", f'Заголовки для {url}: {headers}')
        
        elif command[0] == 'nmap' and command[1] == 'scan':
            if len(command) != 3:
                raise ValueError("Команда 'nmap scan' требует 1 аргумент: [IP].")
            host = command[2]
            progress_bar['value'] = 0
            result = nmap_scan(host, progress_bar, progress_label)
            messagebox.showinfo("Результат", f'Nmap scan for {host}:\n{result}')
        
        elif command[0] == 'openvas' and command[1] == 'scan':
            if len(command) != 3:
                raise ValueError("Команда 'openvas scan' требует 1 аргумент: [IP].")
            host = command[2]
            progress_bar['value'] = 0
            result = openvas_scan(host, progress_bar, progress_label)
            messagebox.showinfo("Результат", f'OpenVAS scan for {host}: {result}')
        
        elif command[0] == 'train' and command[1] == 'model':
            if len(command) != 3:
                raise ValueError("Команда 'train model' требует 1 аргумент: [файл данных].")
            data_file = command[2]
            progress_bar['value'] = 0
            model = train_and_predict_vulnerabilities(data_file)
            messagebox.showinfo("Результат", f'Модель обучена и готова к использованию.')
        
        elif command[0] == 'predict' and command[1] == 'vulnerabilities':
            if len(command) != 3:
                raise ValueError("Команда 'predict vulnerabilities' требует 1 аргумент: [файл данных].")
            data_file = command[2]
            progress_bar['value'] = 0
            new_data = pd.read_csv(data_file)
            model = train_and_predict_vulnerabilities('trained_model.pkl')  # Используем предварительно обученную модель
            predictions = predict_vulnerabilities(model, new_data)
            messagebox.showinfo("Результат", f'Предсказания уязвимостей: {predictions}')
        
        else:
            raise ValueError('Неизвестная команда')
    
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

# Создание основного окна
root = tk.Tk()
root.title("Network Analysis Tool from Anton Bazhin for SovkomBank Tech.")

# Установка размера окна
root.geometry("600x500")

# Создание элементов GUI
label = tk.Label(root, text="Введите команду:")
label.pack(pady=10)

# Окно ввода команды
command_entry = tk.Entry(root, width=60)
command_entry.pack(pady=10)

execute_button = tk.Button(root, text="Выполнить", command=execute_command)
execute_button.pack(pady=10)

# Индикатор прогресса
progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
progress_bar.pack(pady=10)

# Текст для отображения процентов загрузки
progress_label = tk.Label(root, text="")
progress_label.pack(pady=10)

# Комментарии с примерами команд
examples_label = tk.Label(root, text="Примеры команд:\n"
                                     "1. scan ports [IP] [порты]: scan ports 192.168.1.1 22,80,443\n"
                                     "2. check ip [IP]: check ip 8.8.8.8\n"
                                     "3. analyze website [URL]: analyze website http://example.com\n"
                                     "4. nmap scan [IP]: nmap scan 192.168.1.1\n"
                                     "5. openvas scan [IP]: openvas scan 192.168.1.1\n"
                                     "6. train model [data file]: train model data.csv\n"
                                     "7. predict vulnerabilities [data file]: predict vulnerabilities data.csv\n",
                          justify="left")
examples_label.pack(pady=10)

# Запуск основного цикла
root.mainloop()
