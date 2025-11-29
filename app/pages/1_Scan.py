"""
Scan Controller Page - запуск SAST/DAST/SBOM сканувань
"""

import streamlit as st
import sys
from pathlib import Path
import json
import subprocess
from datetime import datetime
import time

# Setup paths
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

st.set_page_config(page_title="Scan Controller", page_icon="🔍", layout="wide")


# Helper functions to check if tools are installed
def check_semgrep_installed():
    """Check if Semgrep is installed"""
    try:
        result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def check_nuclei_installed():
    """Check if Nuclei is installed"""
    try:
        result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def check_trivy_installed():
    """Check if Trivy is installed"""
    try:
        result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

st.markdown("# 🔍 Scan Controller")
st.markdown("### Запуск сканувань на вразливості")

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False

# Target selection
st.markdown("## 1️⃣ Оберіть ціль сканування")

targets = {
    "Vulnerable Flask App": {
        "path": str(ROOT / "targets" / "flask-app"),
        "url": "http://localhost:5001",
        "type": "custom",
        "description": "Кастомний Flask додаток з вразливостями SQLi, XSS, Path Traversal"
    },
    "DVWA": {
        "path": str(ROOT / "fixes" / "dvwa"),
        "url": "http://localhost:8080",
        "type": "external",
        "description": "Damn Vulnerable Web Application (DVWA)"
    }
}

col1, col2 = st.columns([1, 2])

with col1:
    selected_target = st.selectbox(
        "Цільовий додаток:",
        list(targets.keys()),
        help="Оберіть додаток для сканування"
    )

with col2:
    target_info = targets[selected_target]
    st.info(f"📁 **Шлях:** `{target_info['path']}`\n\n🌐 **URL:** `{target_info['url']}`\n\n📝 {target_info['description']}")

# Scan configuration
st.markdown("## 2️⃣ Налаштування сканування")

col1, col2, col3 = st.columns(3)

with col1:
    run_sast = st.checkbox("✅ SAST (Semgrep)", value=True, help="Static Application Security Testing")
    if run_sast:
        sast_ruleset = st.selectbox("Набір правил:", ["auto", "security", "owasp-top-10"], key="sast_rules")

with col2:
    run_dast = st.checkbox("✅ DAST (Nuclei)", value=True, help="Dynamic Application Security Testing")
    if run_dast:
        dast_templates = st.selectbox("Шаблони:", ["cves", "vulnerabilities", "all"], key="dast_templates")

with col3:
    run_sbom = st.checkbox("✅ SBOM (Trivy)", value=True, help="Software Bill of Materials + CVE scan")
    if run_sbom:
        sbom_severity = st.selectbox("Min severity:", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=1, key="sbom_sev")

# Advanced options
with st.expander("⚙️ Додаткові налаштування"):
    col1, col2 = st.columns(2)
    with col1:
        max_findings = st.number_input("Макс. кількість findings:", min_value=10, max_value=1000, value=100)
        timeout = st.number_input("Timeout (сек):", min_value=60, max_value=3600, value=300)
    with col2:
        output_format = st.selectbox("Формат виводу:", ["SARIF", "JSON", "Both"], index=2)
        save_raw = st.checkbox("Зберегти raw output", value=True)

# Run scans
st.markdown("## 3️⃣ Запуск сканування")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    if st.button("🚀 Запустити всі обрані сканування", type="primary", disabled=st.session_state.scan_running):
        st.session_state.scan_running = True
        
        # Check which tools are installed
        tools_status = {
            "Semgrep": check_semgrep_installed() if run_sast else True,
            "Nuclei": check_nuclei_installed() if run_dast else True,
            "Trivy": check_trivy_installed() if run_sbom else True
        }
        
        # Show tool status
        missing_tools = [tool for tool, installed in tools_status.items() if not installed]
        
        if missing_tools:
            st.error(f"❌ Не встановлено: {', '.join(missing_tools)}")
            
            if not tools_status.get("Semgrep", True):
                st.warning("**Semgrep** не встановлено")
                st.code("pip install semgrep", language="powershell")
            
            if not tools_status.get("Nuclei", True):
                st.warning("**Nuclei** не встановлено")
                st.markdown("📥 Завантажити: [GitHub Releases](https://github.com/projectdiscovery/nuclei/releases)")
                with st.expander("Швидке встановлення Nuclei"):
                    st.code("""# Створити папку
mkdir C:\\tools\\nuclei
cd C:\\tools\\nuclei

# Завантажити останню версію з GitHub Releases
# Наприклад: nuclei_3.1.0_windows_amd64.zip

# Розпакувати nuclei.exe
# Додати C:\\tools\\nuclei до PATH

# Перевірити
nuclei -version""", language="powershell")
            
            if not tools_status.get("Trivy", True):
                st.warning("**Trivy** не встановлено")
                st.code("choco install trivy", language="powershell")
                st.markdown("📥 Або завантажити: [GitHub Releases](https://github.com/aquasecurity/trivy/releases)")
            
            st.info("💡 Після встановлення перезапустіть термінал та Streamlit")
            st.session_state.scan_running = False
            st.stop()
        
        # Create scan directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = ROOT / "scans" / f"{selected_target.lower().replace(' ', '_')}_{timestamp}"
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Save scan config
        config = {
            "timestamp": timestamp,
            "target": selected_target,
            "target_path": target_info['path'],
            "target_url": target_info['url'],
            "scans": {
                "sast": run_sast,
                "dast": run_dast,
                "sbom": run_sbom
            },
            "config": {
                "sast_ruleset": sast_ruleset if run_sast else None,
                "dast_templates": dast_templates if run_dast else None,
                "sbom_severity": sbom_severity if run_sbom else None,
                "max_findings": max_findings,
                "timeout": timeout
            }
        }
        
        with open(scan_dir / "config.json", "w") as f:
            json.dump(config, f, indent=2)
        
        st.success(f"✅ Створено директорію сканування: `{scan_dir.name}`")
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        total_scans = sum([run_sast, run_dast, run_sbom])
        current_scan = 0
        
        # SAST - Semgrep
        if run_sast:
            status_text.text("🔍 Запуск Semgrep (SAST)...")
            progress_bar.progress(current_scan / total_scans)
            
            try:
                # Check if semgrep is installed
                result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
                
                cmd = [
                    "semgrep",
                    "--config", f"{sast_ruleset}" if sast_ruleset == "auto" else f"p/{sast_ruleset}",
                    "--json",
                    "--output", str(scan_dir / "semgrep.json"),
                    target_info['path']
                ]
                
                with st.spinner("Сканування Semgrep..."):
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                    
                if result.returncode == 0 or result.returncode == 1:  # 1 = findings found
                    st.success("✅ Semgrep завершено")
                    # Also save SARIF
                    cmd_sarif = cmd.copy()
                    cmd_sarif[-2] = str(scan_dir / "semgrep.sarif")
                    cmd_sarif.insert(-2, "--sarif")
                    subprocess.run(cmd_sarif, capture_output=True, timeout=timeout)
                else:
                    st.warning(f"⚠️ Semgrep завершився з помилкою: {result.stderr}")
                    
            except FileNotFoundError:
                st.error("❌ Semgrep не встановлено. Встановіть: `pip install semgrep`")
            except subprocess.TimeoutExpired:
                st.error("❌ Semgrep перевищив timeout")
            except Exception as e:
                st.error(f"❌ Помилка Semgrep: {e}")
            
            current_scan += 1
            progress_bar.progress(current_scan / total_scans)
        
        # DAST - Nuclei
        if run_dast:
            status_text.text("🌐 Запуск Nuclei (DAST)...")
            progress_bar.progress(current_scan / total_scans)
            
            try:
                # Check if target is running
                import socket
                url_parts = target_info['url'].replace('http://', '').split(':')
                host = url_parts[0]
                port = int(url_parts[1]) if len(url_parts) > 1 else 80
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result != 0:
                    st.warning(f"⚠️ Ціль не доступна на {target_info['url']}. Переконайтесь що додаток запущено.")
                else:
                    cmd = [
                        "nuclei",
                        "-u", target_info['url'],
                        "-t", dast_templates if dast_templates != "all" else "",
                        "-json",
                        "-o", str(scan_dir / "nuclei.json")
                    ]
                    
                    if dast_templates == "all":
                        cmd.remove("-t")
                        cmd.remove("")
                    
                    with st.spinner("Сканування Nuclei..."):
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                        
                    if result.returncode == 0:
                        st.success("✅ Nuclei завершено")
                    else:
                        st.warning(f"⚠️ Nuclei: {result.stderr}")
                        
            except FileNotFoundError:
                st.error("❌ Nuclei не встановлено. Встановіть з https://github.com/projectdiscovery/nuclei")
            except Exception as e:
                st.error(f"❌ Помилка Nuclei: {e}")
            
            current_scan += 1
            progress_bar.progress(current_scan / total_scans)
        
        # SBOM - Trivy
        if run_sbom:
            status_text.text("📦 Запуск Trivy (SBOM + CVE)...")
            progress_bar.progress(current_scan / total_scans)
            
            try:
                # SBOM generation
                cmd_sbom = [
                    "trivy",
                    "fs",
                    "--format", "cyclonedx",
                    "--output", str(scan_dir / "sbom.json"),
                    target_info['path']
                ]
                
                with st.spinner("Генерація SBOM..."):
                    subprocess.run(cmd_sbom, capture_output=True, text=True, timeout=timeout)
                
                # Vulnerability scan
                cmd_vuln = [
                    "trivy",
                    "fs",
                    "--format", "sarif",
                    "--severity", f"{sbom_severity},CRITICAL" if sbom_severity != "CRITICAL" else "CRITICAL",
                    "--output", str(scan_dir / "trivy.sarif"),
                    target_info['path']
                ]
                
                with st.spinner("Сканування вразливостей..."):
                    result = subprocess.run(cmd_vuln, capture_output=True, text=True, timeout=timeout)
                
                if result.returncode == 0:
                    st.success("✅ Trivy завершено")
                else:
                    st.warning(f"⚠️ Trivy: {result.stderr}")
                    
            except FileNotFoundError:
                st.error("❌ Trivy не встановлено. Встановіть з https://github.com/aquasecurity/trivy")
            except Exception as e:
                st.error(f"❌ Помилка Trivy: {e}")
            
            current_scan += 1
            progress_bar.progress(1.0)
        
        status_text.text("✅ Всі сканування завершено!")
        st.session_state.scan_running = False
        st.session_state.last_scan_dir = str(scan_dir)
        
        st.balloons()
        st.success(f"🎉 Сканування завершено! Результати збережено в: `{scan_dir.name}`")
        
        # Show summary
        st.markdown("### 📊 Короткий звіт")
        
        files = list(scan_dir.glob("*"))
        for file in files:
            if file.suffix in ['.json', '.sarif']:
                size_kb = file.stat().st_size / 1024
                st.text(f"📄 {file.name}: {size_kb:.1f} KB")

with col2:
    if st.button("⏹️ Зупинити", disabled=not st.session_state.scan_running):
        st.session_state.scan_running = False
        st.warning("Сканування зупинено")

with col3:
    if st.button("🔄 Скинути"):
        st.session_state.scan_results = {}
        st.rerun()

# Show recent scans
st.markdown("## 📜 Історія сканувань")

scan_root = ROOT / "scans"
if scan_root.exists():
    scans = sorted(scan_root.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)[:10]
    
    if scans:
        st.markdown("Останні 10 сканувань:")
        
        for scan in scans:
            config_file = scan / "config.json"
            if config_file.exists():
                with open(config_file) as f:
                    config = json.load(f)
                
                with st.expander(f"📁 {scan.name} - {config.get('target', 'Unknown')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.json(config)
                    with col2:
                        files = list(scan.glob("*"))
                        st.markdown("**Файли:**")
                        for file in files:
                            st.text(f"📄 {file.name}")
    else:
        st.info("Історія порожня. Запустіть перше сканування!")
else:
    st.info("Директорія сканувань ще не створена")
