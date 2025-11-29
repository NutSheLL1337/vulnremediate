# 🛡️ VulnRemediate PoC

**Automated Vulnerability Detection & Remediation System**

Система автоматичного виявлення та виправлення вразливостей у веб-додатках (Дипломний проект 2025)

## 📋 Опис проекту

VulnRemediate PoC — це прототип системи, що автоматично виявляє вразливості у веб-додатках, пріоритизує їх за ризиками та генерує патчі з можливістю тестування у безпечному sandbox-середовищі.

### Можливості

- **🔍 Сканування** - SAST (Semgrep), DAST (Nuclei), SBOM/CVE (Trivy)
- **📊 Аналіз** - Нормалізація SARIF, фільтрація, пріоритизація
- **🔧 Remediation** - Автоматична генерація патчів на основі шаблонів
- **✅ Тестування** - Sandbox тестування патчів у Docker
- **📈 Метрики** - Precision, Recall, FPR, Remediation Success Rate

## 🚀 Швидкий старт

### Передумови

```bash
# Python 3.10+
python --version

# Docker Desktop (для sandbox тестування)
docker --version

# Сканери (встановлюються автоматично або вручну)
pip install semgrep
# Nuclei: https://github.com/projectdiscovery/nuclei
# Trivy: https://github.com/aquasecurity/trivy
```

### Встановлення

```bash
# 1. Клонувати репозиторій
git clone https://github.com/NutSheLL1337/vulnremediate.git
cd vulnremediate

# 2. Встановити залежності
pip install -r requirements.txt

# 3. Запустити Docker контейнери з вразливими додатками
docker-compose up -d

# 4. Переконатись що цілі доступні
curl http://localhost:5001/health  # Vulnerable Flask App
curl http://localhost:8080         # DVWA
```

### Запуск Streamlit UI

```bash
# Запустити Streamlit dashboard
streamlit run app/Home.py

# Або з автоматичним відкриттям в браузері
streamlit run app/Home.py --server.headless false
```

Відкрийте браузер: **http://localhost:8501**

## 📁 Структура проекту

```
vulnremediate/
├── app/                          # Streamlit UI
│   ├── Home.py                   # Головна сторінка
│   ├── pages/
│   │   ├── 1_Scan.py            # Контролер сканування
│   │   ├── 2_Results.py         # Результати сканувань
│   │   ├── 3_Remediate.py       # Генерація патчів
│   │   └── 4_Metrics.py         # Dashboard метрик
│   └── core/                    # Backend логіка
│       ├── scanners/            # Інтеграції сканерів
│       ├── parsers/             # SARIF парсери
│       └── remediation/         # Генератор патчів
├── targets/                      # Вразливі додатки для тестування
│   └── flask-app/               # Custom Flask app з вразливостями
│       ├── app.py               # 8+ типів вразливостей
│       ├── Dockerfile
│       └── tests/
├── scans/                        # Результати сканувань (генеруються)
├── templates/                    # Jinja2 шаблони патчів
├── scripts/                      # CLI скрипти
│   ├── run_pipeline.py          # Повний pipeline
│   ├── normalize_sarif.py       # SARIF → CSV
│   └── correlate_sbom_trivy_semgrep.py
├── docker-compose.yml            # Вразливі додатки
└── requirements.txt
```

## 🎯 Workflow

### 1. Сканування

На сторінці **Scan**:
1. Оберіть цільовий додаток (Vulnerable Flask App або DVWA)
2. Налаштуйте сканери (SAST/DAST/SBOM)
3. Натисніть "Запустити всі обрані сканування"
4. Результати зберігаються в `scans/<timestamp>/`

### 2. Перегляд результатів

На сторінці **Results**:
- Перегляньте знайдені вразливості в таблиці
- Фільтруйте за Severity, Tool, CWE
- Клікніть на рядок для детальної інформації

### 3. Remediation

На сторінці **Remediate**:
- Оберіть вразливість для виправлення
- Переглядайте згенерований патч (side-by-side diff)
- Натисніть "Apply & Test in Sandbox"
- Система застосує патч і запустить тести

### 4. Метрики

На сторінці **Metrics**:
- Dashboard з візуалізаціями
- Експорт даних (JSON, CSV)
- Аналіз ефективності

## 🧪 Vulnerable Flask App

Custom Flask додаток містить наступні вразливості:

| CWE | Тип вразливості | Endpoint |
|-----|-----------------|----------|
| CWE-89 | SQL Injection | `/login` |
| CWE-79 | Cross-Site Scripting (XSS) | `/search` |
| CWE-22 | Path Traversal | `/file` |
| CWE-798 | Hardcoded Credentials | `app.py:22` |
| CWE-327 | Weak Cryptography (MD5) | `/hash` |
| CWE-78 | OS Command Injection | `/ping` |
| CWE-601 | Open Redirect | `/redirect` |

**Тестування:**
```bash
# Запустити Flask app
docker-compose up vulnerable-flask

# Відкрити в браузері
open http://localhost:5001
```

## 📊 Метрики для оцінки

Система розраховує наступні метрики:

- **Precision** - TP / (TP + FP) - якість детекції
- **Recall** - TP / (TP + FN) - повнота покриття
- **F1 Score** - гармонічне середнє Precision і Recall
- **FPR** - False Positive Rate
- **Remediation Success Rate** - скільки патчів пройшли тести
- **Time-to-Remediate** - час від виявлення до виправлення

## 🔧 CLI скрипти

```bash
# Повний pipeline (CLI версія)
python scripts/run_pipeline.py --artifacts scans/latest/

# Нормалізація SARIF
python scripts/normalize_sarif.py --input scan.sarif --output results.csv

# Кореляція SBOM + Trivy + Semgrep
python scripts/correlate_sbom_trivy_semgrep.py \
    --sbom sbom.json \
    --trivy trivy.sarif \
    --semgrep semgrep.csv \
    --outdir results/
```

## 🐳 Docker команди

```bash
# Запустити всі сервіси
docker-compose up -d

# Подивитись логи
docker-compose logs -f vulnerable-flask

# Зупинити
docker-compose down

# Пересобрати Flask app після змін
docker-compose up -d --build vulnerable-flask
```

## 📚 Додаткові матеріали

- **Документація Semgrep:** https://semgrep.dev/docs/
- **Nuclei Templates:** https://github.com/projectdiscovery/nuclei-templates
- **Trivy Guide:** https://aquasecurity.github.io/trivy/
- **SARIF Spec:** https://sarifweb.azurewebsites.net/

## 🎓 Diploma Context

Цей проект є частиною дипломної роботи на тему:
> "Створення концепції та реалізація прототипу (PoC) системи автоматичного виявлення та виправлення вразливостей у веб-додатках"

**Мета дослідження:**
- Поєднання SAST/DAST/SBOM для повного покриття
- Нормалізація результатів через SARIF
- Автоматична генерація патчів
- Оцінка ефективності через метрики (precision, recall, remediation success rate)

## 📝 Ліцензія

MIT License - див. [LICENSE](LICENSE)

## 👤 Автор

**NutSheLL1337**
- GitHub: [@NutSheLL1337](https://github.com/NutSheLL1337)
