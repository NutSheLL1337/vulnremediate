"""
Diagnostic Page - перевірка встановлених інструментів
"""

import streamlit as st
import subprocess
import sys
import os
from pathlib import Path

st.set_page_config(page_title="Diagnostics", page_icon="🔧", layout="wide")

st.markdown("# 🔧 Діагностика системи")
st.markdown("### Перевірка встановлених інструментів та середовища")

# Python info
st.markdown("## 🐍 Python Environment")

col1, col2 = st.columns(2)

with col1:
    st.code(f"Python версія: {sys.version}", language="text")
    st.code(f"Python шлях: {sys.executable}", language="text")

with col2:
    st.code(f"Робоча директорія: {os.getcwd()}", language="text")
    st.code(f"PATH містить: {len(os.environ.get('PATH', '').split(';'))} записів", language="text")

# Check tools
st.markdown("## 🛠️ Сканери")

def check_tool(name, command, version_flag):
    """Check if a tool is installed and return version info"""
    try:
        result = subprocess.run(
            [command, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
            shell=True
        )
        
        if result.returncode == 0:
            version = result.stdout.strip() or result.stderr.strip()
            return True, version
        else:
            return False, f"Error: {result.stderr}"
    except FileNotFoundError:
        return False, "Command not found"
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

# Semgrep
st.markdown("### 1️⃣ Semgrep (SAST)")
semgrep_installed, semgrep_info = check_tool("semgrep", "semgrep", "--version")

if semgrep_installed:
    st.success(f"✅ Semgrep встановлено")
    st.code(semgrep_info, language="text")
else:
    st.error(f"❌ Semgrep не знайдено: {semgrep_info}")
    st.code("pip install semgrep", language="powershell")
    
    # Try alternative check
    st.markdown("**Альтернативна перевірка через python -m:**")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            st.success("✅ Semgrep доступний через python -m semgrep")
            st.code(result.stdout, language="text")
    except Exception as e:
        st.error(f"Також не працює: {e}")

# Nuclei
st.markdown("### 2️⃣ Nuclei (DAST)")
nuclei_installed, nuclei_info = check_tool("nuclei", "nuclei", "-version")

if nuclei_installed:
    st.success(f"✅ Nuclei встановлено")
    st.code(nuclei_info, language="text")
else:
    st.error(f"❌ Nuclei не знайдено: {nuclei_info}")
    st.markdown("📥 Завантажити: https://github.com/projectdiscovery/nuclei/releases")
    
    # Check common locations
    st.markdown("**Перевірка популярних локацій:**")
    common_paths = [
        r"C:\tools\nuclei\nuclei.exe",
        r"C:\Program Files\nuclei\nuclei.exe",
        os.path.expanduser(r"~\go\bin\nuclei.exe"),
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            st.success(f"✅ Знайдено: {path}")
            st.info(f"Додайте до PATH: {os.path.dirname(path)}")
        else:
            st.text(f"❌ Не знайдено: {path}")

# Trivy
st.markdown("### 3️⃣ Trivy (SBOM/CVE)")
trivy_installed, trivy_info = check_tool("trivy", "trivy", "--version")

if trivy_installed:
    st.success(f"✅ Trivy встановлено")
    st.code(trivy_info, language="text")
else:
    st.error(f"❌ Trivy не знайдено: {trivy_info}")
    st.code("choco install trivy", language="powershell")
    
    # Check common locations
    st.markdown("**Перевірка популярних локацій:**")
    common_paths = [
        r"C:\tools\trivy\trivy.exe",
        r"C:\ProgramData\chocolatey\bin\trivy.exe",
        r"C:\Program Files\trivy\trivy.exe",
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            st.success(f"✅ Знайдено: {path}")
            st.info(f"Додайте до PATH: {os.path.dirname(path)}")
        else:
            st.text(f"❌ Не знайдено: {path}")

# PATH inspection
st.markdown("## 📂 PATH Environment Variable")

with st.expander("Показати всі шляхи в PATH"):
    paths = os.environ.get('PATH', '').split(';')
    for i, path in enumerate(paths, 1):
        st.text(f"{i}. {path}")

# Docker check
st.markdown("## 🐳 Docker")

docker_installed, docker_info = check_tool("docker", "docker", "--version")

if docker_installed:
    st.success(f"✅ Docker встановлено")
    st.code(docker_info, language="text")
    
    # Check docker-compose
    compose_installed, compose_info = check_tool("docker-compose", "docker-compose", "--version")
    if compose_installed:
        st.success(f"✅ Docker Compose встановлено")
        st.code(compose_info, language="text")
    else:
        st.warning("⚠️ Docker Compose не знайдено (але може бути вбудований в Docker)")
else:
    st.error(f"❌ Docker не знайдено: {docker_info}")
    st.markdown("📥 Завантажити Docker Desktop: https://www.docker.com/products/docker-desktop/")

# Summary
st.markdown("---")
st.markdown("## 📊 Підсумок")

total_tools = 3
installed_count = sum([semgrep_installed, nuclei_installed, trivy_installed])

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Встановлено інструментів", f"{installed_count}/{total_tools}")

with col2:
    percentage = (installed_count / total_tools) * 100
    st.metric("Готовність", f"{percentage:.0f}%")

with col3:
    if docker_installed:
        st.metric("Docker", "✅ OK")
    else:
        st.metric("Docker", "❌ Missing")

if installed_count == total_tools:
    st.success("🎉 Всі інструменти встановлені! Можна запускати сканування.")
else:
    st.warning(f"⚠️ Встановіть решту інструментів ({total_tools - installed_count}) для повної функціональності.")
    st.info("💡 Порада: після встановлення перезапустіть PowerShell та Streamlit")

# Quick fix section
st.markdown("## 🚀 Швидке виправлення")

st.markdown("""
**Якщо інструменти встановлені але не виявляються:**

1. **Перезапустіть термінал PowerShell**
2. **Перезапустіть Streamlit:**
   ```powershell
   # Ctrl+C у терміналі де працює Streamlit
   streamlit run app/Home.py
   ```
3. **Перевірте PATH вручну:**
   ```powershell
   $env:Path
   ```
4. **Використайте опцію "Пропустити перевірку інструментів" на сторінці Scan**
""")
