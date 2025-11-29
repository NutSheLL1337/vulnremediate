#!/usr/bin/env python3
"""
VulnRemediate PoC - Main Streamlit Application
Automated Vulnerability Detection & Remediation System
"""

import streamlit as st
from pathlib import Path
import sys

# Setup paths
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Page config
st.set_page_config(
    page_title="VulnRemediate PoC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
    }
    .feature-card {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin-bottom: 1rem;
        color: #2c3e50;
    }
    .feature-card h3 {
        color: #667eea;
        margin-bottom: 0.5rem;
    }
    .feature-card p {
        color: #34495e;
        margin-bottom: 0.5rem;
    }
    .feature-card ul {
        color: #34495e;
        margin-left: 1.5rem;
    }
    .feature-card li {
        color: #34495e;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    .metric-card h2 {
        color: #667eea;
        margin: 0.5rem 0;
    }
    .metric-card h3 {
        margin: 0;
    }
    .metric-card p {
        color: #7f8c8d;
        margin: 0;
    }
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.5rem 2rem;
        border-radius: 5px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown("""
<div class="main-header">
    <h1>🛡️ VulnRemediate PoC</h1>
    <h3>Система автоматичного виявлення та виправлення вразливостей</h3>
    <p>Diploma Project 2025 | Automated SAST/DAST/SBOM Analysis</p>
</div>
""", unsafe_allow_html=True)

# Introduction
st.markdown("## 📋 Про систему")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    ### 🎯 Мета проекту
    
    Створення прототипу системи, що автоматично:
    - 🔍 Виявляє вразливості у веб-додатках
    - 📊 Пріоритизує їх за ризиками
    - 🔧 Генерує патчі для виправлення
    - ✅ Тестує патчі у безпечному середовищі
    - 📈 Аналізує ефективність виправлень
    """)

with col2:
    st.markdown("""
    ### 🛠️ Технології
    
    **Сканери:**
    - **Semgrep** - SAST аналіз коду
    - **Nuclei** - DAST веб-сканування
    - **Trivy** - SBOM + CVE сканування
    
    **Середовище:**
    - Docker для ізоляції тестів
    - Python для автоматизації
    - Streamlit для UI
    """)

# Features overview
st.markdown("## ✨ Функціональність")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class="feature-card">
        <h3>🔎 1. Сканування</h3>
        <p>Запуск SAST, DAST та SBOM сканування цільових додатків</p>
        <ul>
            <li>Вибір цілі</li>
            <li>Налаштування сканерів</li>
            <li>Моніторинг прогресу</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="feature-card">
        <h3>📊 2. Аналіз результатів</h3>
        <p>Нормалізація та відображення знайдених вразливостей</p>
        <ul>
            <li>SARIF нормалізація</li>
            <li>Фільтрація за severity</li>
            <li>Детальна інформація</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="feature-card">
        <h3>🔧 3. Remediation</h3>
        <p>Генерація та тестування патчів у sandbox</p>
        <ul>
            <li>Автоматичні патчі</li>
            <li>Side-by-side diff</li>
            <li>Тестування в Docker</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

# Quick stats (if data exists)
st.markdown("## 📊 Поточна статистика")

# Check if there are any scan results
scan_dir = ROOT / "scans"
if scan_dir.exists() and list(scan_dir.glob("*")):
    scan_count = len(list(scan_dir.glob("*")))
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>📁</h3>
            <h2>{}</h2>
            <p>Всього сканувань</p>
        </div>
        """.format(scan_count), unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>🎯</h3>
            <h2>2</h2>
            <p>Цільові додатки</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>🔍</h3>
            <h2>3</h2>
            <p>Активні сканери</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h3>✅</h3>
            <h2>-</h2>
            <p>Успішних патчів</p>
        </div>
        """, unsafe_allow_html=True)
else:
    st.info("🚀 Почніть з запуску першого сканування на сторінці **Scan**")

# Getting started
st.markdown("## 🚀 Швидкий старт")

st.markdown("""
1. **Переконайтесь що Docker запущений** - потрібен для sandbox-тестування
2. **Перейдіть на сторінку 'Scan'** - оберіть цільовий додаток та запустіть сканування
3. **Перегляньте 'Results'** - проаналізуйте знайдені вразливості
4. **Використайте 'Remediate'** - згенеруйте та протестуйте патчі
5. **Перевірте 'Metrics'** - подивіться на загальну ефективність системи
""")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem;">
    <p>🎓 Дипломний проект | VulnRemediate PoC System</p>
    <p><small>Система автоматичного виявлення та виправлення вразливостей у веб-додатках</small></p>
</div>
""", unsafe_allow_html=True)
