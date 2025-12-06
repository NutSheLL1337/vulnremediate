# 🚀 Quick Start Guide - VulnRemediate PoC

## Крок 1: Встановлення залежностей

```powershell
# Встановити Python залежності
pip install -r requirements.txt

# Встановити Semgrep (SAST)
pip install semgrep

# Перевірити версію
semgrep --version
```

## Крок 2: Встановити додаткові інструменти

### Nuclei (DAST Scanner)
```powershell
# Windows (через scoop)
scoop install nuclei

# Або завантажити з:
# https://github.com/projectdiscovery/nuclei/releases
```

### Trivy (SBOM + Vulnerability Scanner)
```powershell
# Windows (через scoop)
scoop install trivy

# Або завантажити з:
# https://github.com/aquasecurity/trivy/releases
```

## Крок 3: Запустити Docker контейнери

```powershell
# Запустити вразливі додатки
docker-compose up -d

# Перевірити що запустились
docker-compose ps

# Переконатись що доступні
curl http://localhost:5001/health  # Flask App
curl http://localhost:8080         # DVWA
```

## Крок 4: Запустити Streamlit UI

```powershell
# З кореня проекту
streamlit run app/Home.py

# Або з автоматичним відкриттям браузера
streamlit run app/Home.py --server.headless false
```

Відкрийте: **http://localhost:8501**

## Крок 5: Виконати перше сканування

1. **Перейдіть на сторінку "Scan"** (ліва панель)
2. **Оберіть ціль:** "Vulnerable Flask App"
3. **Увімкніть всі сканери:**
   - ✅ SAST (Semgrep)
   - ✅ DAST (Nuclei)
   - ✅ SBOM (Trivy)
4. **Натисніть "Запустити всі обрані сканування"**
5. **Дочекайтесь завершення** (прогрес-бар покаже статус)

## Крок 6: Переглянути результати

1. **Перейдіть на "Results"**
2. **Фільтруйте за Severity:** High, Critical
3. **Клікніть на вразливість** для деталей

## Крок 7: Згенерувати патч

1. **Перейдіть на "Remediate"**
2. **Оберіть вразливість для виправлення**
3. **Переглядайте diff коду**
4. **Натисніть "Apply & Test"** (якщо реалізовано)

## Крок 8: Подивитись метрики

1. **Перейдіть на "Metrics"**
2. **Переглядайте графіки та статистику**
3. **Експортуйте дані** (CSV, JSON)

---

## 🐛 Troubleshooting

### Помилка: "Semgrep not found"
```powershell
pip install semgrep
semgrep --version
```

### Помилка: "Cannot connect to Docker"
```powershell
# Переконатись що Docker Desktop запущений
docker ps

# Перезапустити контейнери
docker-compose down
docker-compose up -d
```

### Помилка: "Port already in use"
```powershell
# Знайти що використовує порт
netstat -ano | findstr :5001

# Змінити порт в docker-compose.yml
# або зупинити конфліктуючий процес
```

### Streamlit не відкривається
```powershell
# Перевірити що працює
netstat -ano | findstr :8501

# Спробувати інший порт
streamlit run app/Home.py --server.port 8502
```

---

## 📊 Очікувані результати

**Після першого сканування Flask App, ви побачите:**

- **SAST (Semgrep):** ~15-20 findings
  - SQL Injection (CWE-89)
  - XSS (CWE-79)
  - Hardcoded secrets (CWE-798)
  - Weak crypto (CWE-327)
  - Command Injection (CWE-78)

- **DAST (Nuclei):** ~5-10 findings
  - Залежить від запущених шаблонів

- **SBOM (Trivy):** ~10-50 CVE
  - Залежності Flask app (Flask, Werkzeug, etc.)

---

## 🎯 Для презентації диплому

### Демонстрація №1: Виявлення SQL Injection
1. Запустити сканування Flask App
2. Показати знайдену вразливість CWE-89
3. Показати код: `/login` endpoint
4. Показати експлойт: `admin' OR '1'='1`

### Демонстрація №2: Автоматичне виправлення
1. Вибрати SQL Injection
2. Показати згенерований патч
3. Пояснити як працює parameterized query
4. Показати side-by-side diff

### Демонстрація №3: Метрики
1. Показати dashboard
2. Пояснити Precision/Recall
3. Показати Remediation Success Rate
4. Експортувати в CSV для аналізу

---

## ✅ Checklist перед захистом

- [ ] Docker контейнери запущені
- [ ] Streamlit UI працює
- [ ] Є хоча б 2-3 успішних сканування
- [ ] Згенеровані метрики
- [ ] Підготовлені скріншоти
- [ ] Записане демо-відео (5 хв)
- [ ] Презентація PowerPoint готова
- [ ] Пояснювальна записка завершена

---

**Успіхів на захисті! 🎓**
