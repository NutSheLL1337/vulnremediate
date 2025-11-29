# 📦 Встановлення сканерів для VulnRemediate PoC

## Огляд

Для роботи системи потрібні 3 інструменти безпеки:

| Інструмент | Призначення | Складність встановлення |
|------------|-------------|------------------------|
| **Semgrep** | SAST (статичний аналіз коду) | ⭐ Легко (pip) |
| **Nuclei** | DAST (динамічне тестування) | ⭐⭐ Середньо (binary) |
| **Trivy** | SBOM + CVE сканування | ⭐⭐ Середньо (chocolatey/binary) |

---

## 1️⃣ Semgrep (SAST)

### Windows

**Через pip (рекомендовано):**

```powershell
pip install semgrep
```

**Перевірка:**

```powershell
semgrep --version
```

**Очікуваний результат:**
```
1.50.0
```

---

## 2️⃣ Nuclei (DAST)

### Варіант 1: Завантаження бінарного файлу (найпростіше)

1. **Відкрийте PowerShell з правами адміністратора**

2. **Створіть директорію для інструментів:**

```powershell
mkdir C:\tools\nuclei
cd C:\tools\nuclei
```

3. **Завантажте останню версію:**

Перейдіть на https://github.com/projectdiscovery/nuclei/releases

Завантажте файл типу: `nuclei_X.X.X_windows_amd64.zip`

Наприклад: `nuclei_3.1.0_windows_amd64.zip`

4. **Розпакуйте архів:**

```powershell
# Якщо завантажили в Downloads
Expand-Archive -Path "$env:USERPROFILE\Downloads\nuclei_3.1.0_windows_amd64.zip" -DestinationPath C:\tools\nuclei
```

5. **Додайте до PATH:**

```powershell
# Тимчасово (до закриття терміналу)
$env:Path += ";C:\tools\nuclei"

# Або постійно через UI:
# 1. Натисніть Win + X → System
# 2. Advanced system settings → Environment Variables
# 3. У "System variables" знайдіть "Path" → Edit
# 4. Додайте: C:\tools\nuclei
# 5. OK → OK → OK
```

6. **Перевірка:**

```powershell
# Закрийте і відкрийте PowerShell заново
nuclei -version
```

**Очікуваний результат:**
```
[INF] Current nuclei version: v3.1.0
```

### Варіант 2: Через Go (якщо встановлений)

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## 3️⃣ Trivy (SBOM/CVE Scanner)

### Варіант 1: Через Chocolatey (рекомендовано)

1. **Встановіть Chocolatey** (якщо ще не встановлений):

```powershell
# PowerShell з правами адміністратора
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

2. **Встановіть Trivy:**

```powershell
choco install trivy
```

3. **Перевірка:**

```powershell
trivy --version
```

### Варіант 2: Завантаження бінарного файлу

1. **Створіть директорію:**

```powershell
mkdir C:\tools\trivy
cd C:\tools\trivy
```

2. **Завантажте з GitHub:**

Перейдіть на https://github.com/aquasecurity/trivy/releases

Завантажте: `trivy_X.X.X_Windows-64bit.zip`

Наприклад: `trivy_0.48.0_Windows-64bit.zip`

3. **Розпакуйте:**

```powershell
Expand-Archive -Path "$env:USERPROFILE\Downloads\trivy_0.48.0_Windows-64bit.zip" -DestinationPath C:\tools\trivy
```

4. **Додайте до PATH:**

```powershell
$env:Path += ";C:\tools\trivy"
```

Або додайте постійно через System Properties → Environment Variables

5. **Перевірка:**

```powershell
# Закрийте і відкрийте PowerShell
trivy --version
```

**Очікуваний результат:**
```
Version: 0.48.0
```

---

## ✅ Перевірка всіх інструментів

Після встановлення всіх інструментів виконайте:

```powershell
# Перевірити всі інструменти
semgrep --version
nuclei -version
trivy --version

# Якщо всі команди працюють - готово! 🎉
```

---

## 🐛 Troubleshooting

### Проблема: "command not found" після встановлення

**Рішення:**
1. Закрийте і відкрийте PowerShell заново
2. Перевірте що PATH оновлено:
   ```powershell
   $env:Path
   ```
3. Перезавантажте комп'ютер (якщо PATH додавали через UI)

### Проблема: Semgrep дуже повільно працює

**Рішення:**
Це нормально для першого запуску - Semgrep завантажує правила.
При наступних запусках буде швидше.

### Проблема: Nuclei не знаходить шаблони

**Рішення:**
```powershell
# Оновити шаблони Nuclei
nuclei -update-templates
```

### Проблема: Trivy не може підключитись до DB

**Рішення:**
```powershell
# Очистити кеш
trivy --clear-cache

# Оновити DB
trivy image --download-db-only
```

---

## 🚀 Швидкий старт після встановлення

1. **Запустити Docker контейнери:**

```powershell
cd C:\Users\holna\vulnremediate
docker-compose up -d
```

2. **Запустити Streamlit:**

```powershell
streamlit run app/Home.py
```

3. **Відкрити браузер:**

http://localhost:8501

4. **Перейти на сторінку Scan і запустити сканування!**

---

## 📚 Додаткові ресурси

- **Semgrep Docs:** https://semgrep.dev/docs/
- **Nuclei Docs:** https://docs.projectdiscovery.io/tools/nuclei
- **Trivy Docs:** https://aquasecurity.github.io/trivy/

---

**Успіхів! 🎓**
