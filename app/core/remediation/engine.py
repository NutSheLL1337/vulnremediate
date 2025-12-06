"""
Remediation Engine - генерує рекомендації для виправлення вразливостей
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape


class RemediationEngine:
    """Генератор remediation templates на основі знайдених вразливостей"""
    
    # Mapping vulnerability types to template files
    VULNERABILITY_TEMPLATES = {
        'sql-injection': 'sql_injection.j2',
        'sqli': 'sql_injection.j2',
        'sql': 'sql_injection.j2',
        'xss': 'xss.j2',
        'cross-site-scripting': 'xss.j2',
        'command-injection': 'command_injection.j2',
        'command': 'command_injection.j2',
        'rce': 'command_injection.j2',
        'path-traversal': 'path_traversal.j2',
        'traversal': 'path_traversal.j2',
        'lfi': 'path_traversal.j2',
        'hardcoded-credentials': 'hardcoded_credentials.j2',
        'hardcoded-password': 'hardcoded_credentials.j2',
        'hardcoded-secret': 'hardcoded_credentials.j2',
    }
    
    def __init__(self, templates_dir: Path = None):
        """
        Ініціалізація remediation engine
        
        Args:
            templates_dir: Директорія з Jinja2 templates
        """
        if templates_dir is None:
            # Default: templates/remediation у root проекту
            templates_dir = Path(__file__).parent.parent.parent.parent / "templates" / "remediation"
        
        self.templates_dir = templates_dir
        
        # Ініціалізація Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def detect_vulnerability_type(self, vulnerability: Dict[str, Any]) -> str:
        """
        Визначити тип вразливості на основі метаданих
        
        Args:
            vulnerability: Dict з даними про вразливість
            
        Returns:
            Тип вразливості (sql-injection, xss, тощо)
        """
        # Check check_id або rule_id
        check_id = vulnerability.get('check_id', '').lower()
        rule_id = vulnerability.get('rule_id', '').lower()
        message = vulnerability.get('message', '').lower()
        template_id = vulnerability.get('template-id', '').lower()
        
        combined_text = f"{check_id} {rule_id} {message} {template_id}"
        
        # Pattern matching для визначення типу
        if any(keyword in combined_text for keyword in ['sql', 'sqli', 'injection']):
            if 'command' in combined_text or 'exec' in combined_text or 'rce' in combined_text:
                return 'command-injection'
            return 'sql-injection'
        
        if any(keyword in combined_text for keyword in ['xss', 'cross-site', 'script']):
            return 'xss'
        
        if any(keyword in combined_text for keyword in ['command', 'exec', 'rce', 'injection']):
            return 'command-injection'
        
        if any(keyword in combined_text for keyword in ['path', 'traversal', 'lfi', 'file-inclusion']):
            return 'path-traversal'
        
        if any(keyword in combined_text for keyword in ['hardcoded', 'password', 'secret', 'credential']):
            return 'hardcoded-credentials'
        
        return 'unknown'
    
    def extract_vulnerability_data(self, vuln: Dict[str, Any], source: str = 'semgrep') -> Dict[str, Any]:
        """
        Екстракт structured data з різних форматів сканерів
        
        Args:
            vuln: Raw vulnerability data
            source: Тип сканера (semgrep, nuclei, trivy)
            
        Returns:
            Normalized vulnerability data
        """
        if source == 'semgrep':
            return {
                'title': vuln.get('extra', {}).get('message', 'Vulnerability detected'),
                'severity': vuln.get('extra', {}).get('severity', 'UNKNOWN').lower(),
                'file': vuln.get('path', 'unknown'),
                'line': vuln.get('start', {}).get('line', 0),
                'check_id': vuln.get('check_id', ''),
                'code_snippet': vuln.get('extra', {}).get('lines', ''),
                'language': self._detect_language(vuln.get('path', '')),
                'description': vuln.get('extra', {}).get('message', ''),
                'owasp_reference': vuln.get('extra', {}).get('metadata', {}).get('owasp', ''),
                'cwe': vuln.get('extra', {}).get('metadata', {}).get('cwe', ''),
            }
        
        elif source == 'nuclei':
            return {
                'title': vuln.get('info', {}).get('name', 'Vulnerability detected'),
                'severity': vuln.get('info', {}).get('severity', 'unknown'),
                'file': vuln.get('matched-at', 'N/A (Runtime)'),
                'line': 'N/A (DAST)',
                'template-id': vuln.get('template-id', ''),
                'code_snippet': vuln.get('request', 'N/A'),
                'language': 'http',
                'description': vuln.get('info', {}).get('description', ''),
                'owasp_reference': '',
                'matcher_name': vuln.get('matcher-name', ''),
            }
        
        return {}
    
    def _detect_language(self, filepath: str) -> str:
        """Визначити мову програмування по розширенню файлу"""
        ext = Path(filepath).suffix.lower()
        
        language_map = {
            '.php': 'php',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.rb': 'ruby',
            '.go': 'go',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
        }
        
        return language_map.get(ext, 'text')
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """
        Генерувати remediation document для вразливості
        
        Args:
            vulnerability: Normalized vulnerability data
            
        Returns:
            Markdown document з рекомендаціями
        """
        vuln_type = self.detect_vulnerability_type(vulnerability)
        template_file = self.VULNERABILITY_TEMPLATES.get(vuln_type)
        
        if not template_file:
            return self._generate_generic_remediation(vulnerability)
        
        try:
            template = self.jinja_env.get_template(template_file)
            return template.render(vulnerability=vulnerability)
        except Exception as e:
            return f"# Remediation Template Error\n\nCould not generate remediation: {str(e)}"
    
    def _generate_generic_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """Fallback generic remediation для невідомих типів"""
        return f"""# Vulnerability Remediation

**Title:** {vulnerability.get('title', 'Unknown Vulnerability')}
**Severity:** {vulnerability.get('severity', 'unknown')}
**File:** {vulnerability.get('file', 'unknown')}
**Line:** {vulnerability.get('line', 'N/A')}

## Description

{vulnerability.get('description', 'No description available')}

## General Recommendations

1. Review the vulnerable code carefully
2. Validate all user inputs
3. Use security libraries and frameworks
4. Follow OWASP guidelines
5. Test the fix thoroughly

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Database: https://cwe.mitre.org/
"""
    
    def analyze_scan_results(self, scan_dir: Path) -> List[Dict[str, Any]]:
        """
        Проаналізувати результати сканування і генерувати remediation
        
        Args:
            scan_dir: Директорія з результатами сканування
            
        Returns:
            List з remediation recommendations
        """
        remediations = []
        
        # Parse Semgrep results
        semgrep_file = scan_dir / "semgrep.json"
        if semgrep_file.exists():
            with open(semgrep_file, encoding='utf-8') as f:
                data = json.load(f)
                
                # Обмежуємо до 5 найбільш critical для demo
                vulnerabilities = data.get('results', [])[:5]
                
                for vuln in vulnerabilities:
                    vuln_data = self.extract_vulnerability_data(vuln, source='semgrep')
                    vuln_type = self.detect_vulnerability_type(vuln_data)
                    remediation_text = self.generate_remediation(vuln_data)
                    
                    remediations.append({
                        'source': 'semgrep',
                        'type': vuln_type,
                        'severity': vuln_data['severity'],
                        'file': vuln_data['file'],
                        'line': vuln_data['line'],
                        'remediation': remediation_text,
                        'raw_data': vuln_data
                    })
        
        # Parse Nuclei results
        nuclei_file = scan_dir / "nuclei.json"
        if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
            try:
                with open(nuclei_file, encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    # Nuclei outputs JSON Lines format
                    for line in lines[:3]:  # Обмежуємо до 3 для demo
                        if line.strip():
                            vuln = json.loads(line)
                            vuln_data = self.extract_vulnerability_data(vuln, source='nuclei')
                            vuln_type = self.detect_vulnerability_type(vuln_data)
                            remediation_text = self.generate_remediation(vuln_data)
                            
                            remediations.append({
                                'source': 'nuclei',
                                'type': vuln_type,
                                'severity': vuln_data['severity'],
                                'file': vuln_data['file'],
                                'line': vuln_data['line'],
                                'remediation': remediation_text,
                                'raw_data': vuln_data
                            })
            except Exception as e:
                print(f"Error parsing Nuclei results: {e}")
        
        return remediations
    
    def generate_summary_report(self, remediations: List[Dict[str, Any]]) -> str:
        """
        Генерувати підсумковий remediation report
        
        Args:
            remediations: List з remediation recommendations
            
        Returns:
            Markdown summary report
        """
        if not remediations:
            return "# Remediation Report\n\nNo vulnerabilities found or no remediations generated."
        
        # Group by type
        by_type = {}
        for rem in remediations:
            vuln_type = rem['type']
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(rem)
        
        # Generate summary
        report = "# Vulnerability Remediation Summary\n\n"
        report += f"**Total Vulnerabilities Analyzed:** {len(remediations)}\n\n"
        
        report += "## Vulnerability Breakdown\n\n"
        report += "| Type | Count | Severity |\n"
        report += "|------|-------|----------|\n"
        
        for vuln_type, items in by_type.items():
            severities = [item['severity'] for item in items]
            max_severity = max(severities, key=lambda x: ['low', 'medium', 'high', 'critical'].index(x) if x in ['low', 'medium', 'high', 'critical'] else 0)
            report += f"| {vuln_type} | {len(items)} | {max_severity} |\n"
        
        report += "\n## Priority Recommendations\n\n"
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
        sorted_rems = sorted(remediations, key=lambda x: severity_order.get(x['severity'], 4))
        
        for idx, rem in enumerate(sorted_rems[:5], 1):
            report += f"### {idx}. {rem['type'].replace('-', ' ').title()}\n\n"
            report += f"- **Source:** {rem['source']}\n"
            report += f"- **Severity:** {rem['severity']}\n"
            report += f"- **Location:** {rem['file']}:{rem['line']}\n\n"
        
        return report
