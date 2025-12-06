"""
Docker-based scanners - запуск сканерів через Docker контейнери
Не потребує локального встановлення інструментів
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def check_docker_available() -> bool:
    """Перевірити чи доступний Docker"""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=True
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Docker check failed: {e}")
        return False


def run_semgrep_docker(target_path: Path, output_dir: Path, ruleset: str = "auto") -> Dict[str, Any]:
    """
    Запустити Semgrep через Docker
    
    Args:
        target_path: Шлях до коду для сканування
        output_dir: Директорія для результатів
        ruleset: Набір правил (auto, security, owasp-top-10)
    
    Returns:
        Dict з результатами сканування
    """
    try:
        # Конвертуємо Windows шлях для Docker
        target_path = Path(target_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Output files
        json_output = output_dir / "semgrep.json"
        sarif_output = output_dir / "semgrep.sarif"
        
        # Визначаємо config
        config = f"p/{ruleset}" if ruleset != "auto" else "auto"
        
        # Docker команда для JSON
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            "-v", f"{output_dir}:/output",
            "returntocorp/semgrep",
            "semgrep",
            "--config", config,
            "--json",
            "--output", "/output/semgrep.json",
            "/src"
        ]
        
        logger.info(f"Running Semgrep Docker: {' '.join(docker_cmd)}")
        
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=True
        )
        
        # Semgrep повертає код 1 якщо знайдено findings (це нормально)
        if result.returncode in [0, 1]:
            # Також генеруємо SARIF
            docker_cmd_sarif = [
                "docker", "run", "--rm",
                "-v", f"{target_path}:/src",
                "-v", f"{output_dir}:/output",
                "returntocorp/semgrep",
                "semgrep",
                "--config", config,
                "--sarif",
                "--output", "/output/semgrep.sarif",
                "/src"
            ]
            
            subprocess.run(docker_cmd_sarif, capture_output=True, timeout=300, shell=True)
            
            # Читаємо результати
            if json_output.exists():
                with open(json_output, encoding='utf-8') as f:
                    data = json.load(f)
                    findings_count = len(data.get("results", []))
                    
                return {
                    "success": True,
                    "tool": "semgrep",
                    "findings_count": findings_count,
                    "json_path": str(json_output),
                    "sarif_path": str(sarif_output) if sarif_output.exists() else None,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                return {
                    "success": False,
                    "error": "Output file not created",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
        else:
            return {
                "success": False,
                "error": f"Semgrep failed with code {result.returncode}",
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Semgrep timeout (>5min)"
        }
    except Exception as e:
        logger.error(f"Semgrep Docker error: {e}")
        return {
            "success": False,
            "error": str(e)
        }


def run_trivy_docker(target_path: Path, output_dir: Path, severity: str = "MEDIUM") -> Dict[str, Any]:
    """
    Запустити Trivy через Docker
    
    Args:
        target_path: Шлях до коду
        output_dir: Директорія для результатів
        severity: Мінімальна severity (LOW, MEDIUM, HIGH, CRITICAL)
    
    Returns:
        Dict з результатами
    """
    try:
        target_path = Path(target_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        sbom_output = output_dir / "sbom.json"
        sarif_output = output_dir / "trivy.sarif"
        json_output = output_dir / "trivy.json"
        
        # 1. Генерація SBOM (CycloneDX format)
        sbom_cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            "-v", f"{output_dir}:/output",
            "aquasec/trivy",
            "fs",
            "--format", "cyclonedx",
            "--output", "/output/sbom.json",
            "/src"
        ]
        
        logger.info("Running Trivy SBOM generation...")
        subprocess.run(sbom_cmd, capture_output=True, timeout=300, shell=True)
        
        # 2. Vulnerability scan - включаємо ВСЕ (CVE + misconfigs + secrets)
        vuln_cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            "-v", f"{output_dir}:/output",
            "aquasec/trivy",
            "fs",
            "--format", "json",
            "--severity", f"{severity},HIGH,CRITICAL" if severity == "LOW" else (f"{severity},CRITICAL" if severity != "CRITICAL" else "CRITICAL"),
            "--scanners", "vuln,config,secret",  # ← FIX: додано config та secret scanners
            "--output", "/output/trivy.json",
            "/src"
        ]
        
        logger.info("Running Trivy comprehensive scan (CVE + Config + Secrets)...")
        result = subprocess.run(vuln_cmd, capture_output=True, text=True, timeout=300, shell=True)
        
        # 3. SARIF format
        sarif_cmd = [
            "docker", "run", "--rm",
            "-v", f"{target_path}:/src",
            "-v", f"{output_dir}:/output",
            "aquasec/trivy",
            "fs",
            "--format", "sarif",
            "--severity", f"{severity},HIGH,CRITICAL" if severity == "LOW" else (f"{severity},CRITICAL" if severity != "CRITICAL" else "CRITICAL"),
            "--scanners", "vuln,config,secret",
            "--output", "/output/trivy.sarif",
            "/src"
        ]
        
        subprocess.run(sarif_cmd, capture_output=True, timeout=300, shell=True)
        
        # Підрахунок findings - тепер включаємо Vulnerabilities, Misconfigurations, Secrets
        findings_count = 0
        if json_output.exists():
            with open(json_output, encoding='utf-8') as f:
                data = json.load(f)
                for result_item in data.get("Results", []):
                    findings_count += len(result_item.get("Vulnerabilities", []))
                    findings_count += len(result_item.get("Misconfigurations", []))  # ← FIX
                    findings_count += len(result_item.get("Secrets", []))  # ← FIX
        
        return {
            "success": True,
            "tool": "trivy",
            "findings_count": findings_count,
            "sbom_path": str(sbom_output) if sbom_output.exists() else None,
            "sarif_path": str(sarif_output) if sarif_output.exists() else None,
            "json_path": str(json_output) if json_output.exists() else None,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Trivy timeout"
        }
    except Exception as e:
        logger.error(f"Trivy Docker error: {e}")
        return {
            "success": False,
            "error": str(e)
        }


def run_nuclei_docker(target_url: str, output_dir: Path, templates: str = "cves") -> Dict[str, Any]:
    """
    Запустити Nuclei через Docker
    
    Args:
        target_url: URL для сканування
        output_dir: Директорія для результатів
        templates: Тип шаблонів (cves, vulnerabilities, all)
    
    Returns:
        Dict з результатами
    """
    try:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        json_output = output_dir / "nuclei.json"
        
        # Створюємо volume для nuclei templates (persistent між запусками)
        nuclei_templates_dir = Path.home() / ".nuclei-templates"
        nuclei_templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Custom templates для наших вразливостей
        custom_templates_dir = Path(__file__).parent.parent.parent.parent / "nuclei-templates"
        
        # Крок 1: Оновити templates (якщо потрібно)
        logger.info("Updating Nuclei templates...")
        update_cmd = [
            "docker", "run", "--rm",
            "-v", f"{nuclei_templates_dir}:/root/.local/nuclei-templates",
            "projectdiscovery/nuclei",
            "-update-templates",
            "-silent"
        ]
        
        update_result = subprocess.run(
            update_cmd,
            capture_output=True,
            text=True,
            timeout=120,
            shell=True
        )
        
        logger.info(f"Templates update result: {update_result.returncode}")
        
        # Крок 2: Запустити сканування
        nuclei_cmd = [
            "docker", "run", "--rm",
            "--network", "host",  # Доступ до host network
            "-v", f"{output_dir}:/output",
            "-v", f"{nuclei_templates_dir}:/root/.local/nuclei-templates",  # Mount templates
            "-v", f"{custom_templates_dir}:/custom-templates",  # Custom templates
            "projectdiscovery/nuclei",
            "-u", target_url,
            "-jsonl",  # JSON Lines format
            "-o", "/output/nuclei.json",
            "-silent"  # Менше verbose output
        ]
        
        # Вибір templates в залежності від типу сканування
        if templates == "cves":
            # CVE templates + custom
            nuclei_cmd.extend([
                "-tags", "cve",
                "-t", "/custom-templates/"  # Додаємо custom templates
            ])
        elif templates == "vulnerabilities":
            # Основні вразливості + custom templates (пріоритет)
            nuclei_cmd.extend([
                "-t", "/custom-templates/",  # Спочатку наші templates
                "-tags", "sqli,xss,lfi,rfi,rce,ssrf,xxe,injection,traversal,upload"
            ])
        elif templates == "all":
            # Всі categories + custom
            nuclei_cmd.extend([
                "-t", "/custom-templates/",
                "-tags", "sqli,xss,lfi,rfi,rce,ssrf,xxe,injection,traversal,upload,exposure,misconfiguration,cve"
            ])
        else:
            # Default - тільки наші custom templates
            nuclei_cmd.extend([
                "-t", "/custom-templates/"
            ])
        
        # Додаткові опції для кращої детекції
        nuclei_cmd.extend([
            "-severity", "low,medium,high,critical",  # Всі severity levels
            "-rate-limit", "150",  # Requests per second
            "-timeout", "10",  # Timeout per request
            "-retries", "1"  # Retry failed requests
        ])
        
        logger.info(f"Running Nuclei Docker: {' '.join(nuclei_cmd)}")
        
        result = subprocess.run(
            nuclei_cmd,
            capture_output=True,
            text=True,
            timeout=600,  # DAST може бути довшим
            shell=True
        )
        
        # Підрахунок findings
        findings_count = 0
        if json_output.exists() and json_output.stat().st_size > 0:
            try:
                with open(json_output, encoding='utf-8') as f:
                    # JSON Lines format - кожен рядок це окремий JSON об'єкт
                    lines = f.readlines()
                    findings_count = len([l for l in lines if l.strip() and l.strip().startswith('{')])
            except Exception as e:
                logger.error(f"Error reading Nuclei output: {e}")
        
        # Перевіряємо stderr на критичні помилки
        critical_errors = ["no templates provided", "could not run nuclei"]
        has_critical_error = any(err in result.stderr.lower() for err in critical_errors)
        
        if has_critical_error:
            return {
                "success": False,
                "error": f"Nuclei critical error: {result.stderr}",
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        
        return {
            "success": True,
            "tool": "nuclei",
            "findings_count": findings_count,
            "json_path": str(json_output) if json_output.exists() else None,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Nuclei timeout (>10min)"
        }
    except Exception as e:
        logger.error(f"Nuclei Docker error: {e}")
        return {
            "success": False,
            "error": str(e)
        }
