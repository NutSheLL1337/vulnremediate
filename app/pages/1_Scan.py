"""
Scan Controller Page - запуск SAST/DAST/SBOM сканувань через Docker
"""

import streamlit as st
import sys
from pathlib import Path
import json
from datetime import datetime

# Setup paths
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.core.scanners.docker_scanners import (
    check_docker_available,
    run_semgrep_docker,
    run_trivy_docker,
    run_nuclei_docker
)

st.set_page_config(page_title="Scan Controller", page_icon="🔍", layout="wide")

st.markdown("# 🔍 Scan Controller (Docker Mode)")
st.markdown("### Запуск сканувань на вразливості через Docker контейнери")

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False

# Check Docker availability
docker_available = check_docker_available()

if not docker_available:
    st.error("❌ **Docker не доступний!**")
    st.markdown("""
    Для роботи цього застосунку потрібен Docker.
    
    **Встановлення Docker:**
    1. Завантажте [Docker Desktop для Windows](https://www.docker.com/products/docker-desktop/)
    2. Встановіть та запустіть Docker Desktop
    3. Перезапустіть Streamlit
    
    **Або перевірте чи запущений Docker:**
    ```powershell
    docker --version
    ```
    """)
    st.stop()
else:
    st.success("✅ Docker доступний")

# Target selection
st.markdown("## 1️⃣ Оберіть ціль сканування")

targets = {
    "Vulnerable Flask App": {
        "path": str(ROOT / "targets" / "flask-app"),
        "url": "http://localhost:5001",  # Nuclei з --network host використовує localhost
        "url_display": "http://localhost:5001",
        "type": "custom",
        "description": "Кастомний Flask додаток з вразливостями SQLi, XSS, Path Traversal"
    },
    "DVWA": {
        "path": str(ROOT / "targets" / "dvwa"),
        "url": "http://localhost:8080",  # Nuclei з --network host використовує localhost
        "url_display": "http://localhost:8080",
        "type": "external",
        "description": "Damn Vulnerable Web Application - повний PHP додаток з 10+ типами вразливостей"
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
    st.info(f"📁 **Шлях:** `{target_info['path']}`\n\n🌐 **URL:** `{target_info.get('url_display', target_info['url'])}`\n\n📝 {target_info['description']}")

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
        auto_pull_images = st.checkbox("🐋 Автоматично завантажувати Docker образи", value=True,
                                       help="Якщо образ не знайдено локально, Docker автоматично завантажить його")
    with col2:
        output_format = st.selectbox("Формат виводу:", ["SARIF", "JSON", "Both"], index=2)
        save_raw = st.checkbox("Зберегти raw output", value=True)

# Run scans
st.markdown("## 3️⃣ Запуск сканування")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    if st.button("🚀 Запустити всі обрані сканування", type="primary", disabled=st.session_state.scan_running):
        st.session_state.scan_running = True
        
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
                "output_format": output_format,
                "docker_mode": True
            }
        }
        
        with open(scan_dir / "config.json", "w", encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        st.success(f"✅ Створено директорію сканування: `{scan_dir.name}`")
        
        # Progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        total_scans = sum([run_sast, run_dast, run_sbom])
        current_scan = 0
        
        results_summary = {
            "scans_completed": [],
            "scans_failed": [],
            "total_findings": 0
        }
        
        # SAST - Semgrep (Docker)
        if run_sast:
            status_text.text("🔍 Запуск Semgrep через Docker...")
            progress_bar.progress(current_scan / total_scans)
            
            with st.spinner("Сканування Semgrep (це може зайняти кілька хвилин при першому запуску)..."):
                result = run_semgrep_docker(
                    target_path=Path(target_info['path']),
                    output_dir=scan_dir,
                    ruleset=sast_ruleset
                )
                
                if result.get("success"):
                    findings = result.get("findings_count", 0)
                    results_summary["total_findings"] += findings
                    results_summary["scans_completed"].append(f"Semgrep ({findings} findings)")
                    st.success(f"✅ Semgrep завершено: знайдено {findings} findings")
                else:
                    results_summary["scans_failed"].append(f"Semgrep: {result.get('error', 'Unknown error')}")
                    st.error(f"❌ Помилка Semgrep: {result.get('error')}")
                    with st.expander("Деталі помилки"):
                        st.code(result.get("stderr", "No details"))
            
            current_scan += 1
            progress_bar.progress(current_scan / total_scans)
        
        # DAST - Nuclei (Docker)
        if run_dast:
            status_text.text("🌐 Запуск Nuclei через Docker...")
            progress_bar.progress(current_scan / total_scans)
            
            # Check if target is accessible
            import socket
            url_parts = target_info['url'].replace('http://', '').split(':')
            host = url_parts[0]
            port = int(url_parts[1]) if len(url_parts) > 1 else 80
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            target_available = sock.connect_ex((host, port)) == 0
            sock.close()
            
            if not target_available:
                st.warning(f"⚠️ Ціль не доступна на порту {port}. Переконайтесь що додаток запущено (docker-compose up).")
                results_summary["scans_failed"].append("Nuclei: Target not available")
            else:
                with st.spinner("Сканування Nuclei (DAST може тривати довше)..."):
                    result = run_nuclei_docker(
                        target_url=target_info['url'],
                        output_dir=scan_dir,
                        templates=dast_templates
                    )
                    
                    if result.get("success"):
                        findings = result.get("findings_count", 0)
                        results_summary["total_findings"] += findings
                        results_summary["scans_completed"].append(f"Nuclei ({findings} findings)")
                        st.success(f"✅ Nuclei завершено: знайдено {findings} findings")
                    else:
                        results_summary["scans_failed"].append(f"Nuclei: {result.get('error', 'Unknown error')}")
                        st.error(f"❌ Помилка Nuclei: {result.get('error')}")
                        with st.expander("Деталі помилки"):
                            st.code(result.get("stderr", "No details"))
            
            current_scan += 1
            progress_bar.progress(current_scan / total_scans)
        
        # SBOM - Trivy (Docker)
        if run_sbom:
            status_text.text("📦 Запуск Trivy через Docker (SBOM + CVE)...")
            progress_bar.progress(current_scan / total_scans)
            
            with st.spinner("Сканування Trivy (генерація SBOM та аналіз вразливостей)..."):
                result = run_trivy_docker(
                    target_path=Path(target_info['path']),
                    output_dir=scan_dir,
                    severity=sbom_severity
                )
                
                if result.get("success"):
                    findings = result.get("findings_count", 0)
                    results_summary["total_findings"] += findings
                    results_summary["scans_completed"].append(f"Trivy ({findings} CVEs)")
                    st.success(f"✅ Trivy завершено: знайдено {findings} вразливостей")
                else:
                    results_summary["scans_failed"].append(f"Trivy: {result.get('error', 'Unknown error')}")
                    st.error(f"❌ Помилка Trivy: {result.get('error')}")
                    with st.expander("Деталі помилки"):
                        st.code(result.get("stderr", "No details"))
            
            current_scan += 1
            progress_bar.progress(1.0)
        
        # Save results summary
        with open(scan_dir / "summary.json", "w", encoding='utf-8') as f:
            json.dump(results_summary, f, indent=2, ensure_ascii=False)
        
        status_text.text("✅ Всі сканування завершено!")
        st.session_state.scan_running = False
        st.session_state.last_scan_dir = str(scan_dir)
        
        # Show results
        st.balloons()
        st.success(f"🎉 Сканування завершено! Результати збережено в: `{scan_dir.name}`")
        
        # Show summary
        st.markdown("### 📊 Підсумок сканування")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Успішні сканування", len(results_summary["scans_completed"]))
            if results_summary["scans_completed"]:
                for scan in results_summary["scans_completed"]:
                    st.success(f"✅ {scan}")
        
        with col2:
            st.metric("Всього знайдено findings", results_summary["total_findings"])
            if results_summary["scans_failed"]:
                st.warning(f"Невдалі сканування: {len(results_summary['scans_failed'])}")
                for scan in results_summary["scans_failed"]:
                    st.error(f"❌ {scan}")
        
        # Show files
        st.markdown("### 📁 Згенеровані файли")
        files = sorted(list(scan_dir.glob("*")))
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
            summary_file = scan / "summary.json"
            
            if config_file.exists():
                with open(config_file, encoding='utf-8') as f:
                    config = json.load(f)
                
                # Load summary if exists
                summary = None
                if summary_file.exists():
                    with open(summary_file, encoding='utf-8') as f:
                        summary = json.load(f)
                
                summary_text = ""
                if summary:
                    summary_text = f" - {summary.get('total_findings', 0)} findings"
                
                with st.expander(f"📁 {scan.name} - {config.get('target', 'Unknown')}{summary_text}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Конфігурація:**")
                        st.json(config)
                    with col2:
                        st.markdown("**Файли:**")
                        files = sorted(list(scan.glob("*")))
                        for file in files:
                            size_kb = file.stat().st_size / 1024
                            st.text(f"📄 {file.name} ({size_kb:.1f} KB)")
                        
                        if summary:
                            st.markdown("**Результати:**")
                            st.json(summary)
    else:
        st.info("Історія порожня. Запустіть перше сканування!")
else:
    st.info("Директорія сканувань ще не створена")

# Help section
with st.expander("ℹ️ Довідка про Docker режим"):
    st.markdown("""
    ### Чому Docker?
    
    - ✅ **Не потрібно локальне встановлення** Semgrep, Nuclei, Trivy
    - ✅ **Працює однаково** на Windows, Linux, macOS
    - ✅ **Ізоляція**: сканери запускаються в окремих контейнерах
    - ✅ **Портативність**: можна запустити де завгодно з Docker
    
    ### Docker образи
    
    При першому запуску Docker автоматично завантажить:
    - `returntocorp/semgrep` (~500 MB)
    - `projectdiscovery/nuclei` (~100 MB)
    - `aquasec/trivy` (~200 MB)
    
    ### Доступ до локальних додатків
    
    Для доступу з Docker контейнера до додатків на хості використовується спеціальний DNS:
    - `host.docker.internal` - вказує на хост машину
    - Приклад: `http://host.docker.internal:5001` для Flask app
    
    ### Перший запуск
    
    При першому запуску кожного сканера Docker:
    1. Завантажить образ (може зайняти 1-5 хвилин)
    2. Створить контейнер
    3. Запустить сканування
    
    Наступні запуски будуть значно швидшими.
    """)
