# Custom Nuclei Templates

Цей каталог містить custom Nuclei templates для виявлення вразливостей у наших тестових додатках.

## Templates для Flask App

### 1. flask-sqli-login.yaml
**Вразливість:** SQL Injection  
**Endpoint:** `/login`  
**CWE:** CWE-89  
**Severity:** Critical  

**Payloads:**
- `admin' OR '1'='1`
- `admin'--`
- `' OR 1=1--`

### 2. flask-xss-search.yaml
**Вразливість:** Reflected XSS  
**Endpoint:** `/search`  
**CWE:** CWE-79  
**Severity:** High  

**Payloads:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert(1)>`

### 3. flask-path-traversal.yaml
**Вразливість:** Path Traversal  
**Endpoint:** `/file`  
**CWE:** CWE-22  
**Severity:** High  

**Payloads:**
- `../../etc/passwd`
- `..%2F..%2Fetc%2Fpasswd`
- `/etc/passwd`

### 4. flask-command-injection.yaml
**Вразливість:** Command Injection  
**Endpoint:** `/ping`  
**CWE:** CWE-78  
**Severity:** Critical  

**Payloads:**
- `127.0.0.1;id`
- `127.0.0.1|id`
- `127.0.0.1&&id`

## Templates для DVWA

### 5. dvwa-sqli-low.yaml
**Вразливість:** SQL Injection  
**Module:** `/vulnerabilities/sqli/`  
**Security Level:** Low  
**CWE:** CWE-89  

### 6. dvwa-xss-reflected.yaml
**Вразливість:** Reflected XSS  
**Module:** `/vulnerabilities/xss_r/`  
**Security Level:** Low  
**CWE:** CWE-79  

### 7. dvwa-command-injection.yaml
**Вразливість:** Command Injection  
**Module:** `/vulnerabilities/exec/`  
**Security Level:** Low  
**CWE:** CWE-78  

### 8. dvwa-file-inclusion.yaml
**Вразливість:** Local File Inclusion  
**Module:** `/vulnerabilities/fi/`  
**Security Level:** Low  
**CWE:** CWE-98  

## Використання

Templates автоматично монтуються в Docker контейнер при запуску Nuclei через `run_nuclei_docker()`.

```python
# В docker_scanners.py:
-v f"{custom_templates_dir}:/custom-templates"
-t "/custom-templates/"
```

## Структура Template

```yaml
id: unique-template-id

info:
  name: Template Name
  author: vulnremediate
  severity: critical|high|medium|low
  description: Description
  tags: tag1,tag2,tag3

http:
  - method: GET|POST
    path:
      - "{{BaseURL}}/endpoint?param=payload"
    
    matchers:
      - type: word|regex|status
        words: ["match1", "match2"]
```

## Testing

Для тестування templates локально:

```bash
# Nuclei CLI
nuclei -u http://localhost:5001 -t nuclei-templates/flask-sqli-login.yaml

# Або через Docker
docker run --rm --network host \
  -v $(pwd)/nuclei-templates:/templates \
  projectdiscovery/nuclei \
  -u http://localhost:5001 \
  -t /templates/
```

## Очікувані результати

### Flask App (localhost:5001):
- ✅ flask-sqli-login.yaml → SQLi detected
- ✅ flask-xss-search.yaml → XSS detected
- ✅ flask-path-traversal.yaml → Path traversal detected
- ✅ flask-command-injection.yaml → Command injection detected

### DVWA (localhost:8080):
- ✅ dvwa-sqli-low.yaml → SQLi detected
- ✅ dvwa-xss-reflected.yaml → XSS detected
- ✅ dvwa-command-injection.yaml → RCE detected
- ✅ dvwa-file-inclusion.yaml → LFI detected

**Total expected findings:** 8+

## References

- [Nuclei Template Guide](https://nuclei.projectdiscovery.io/templating-guide/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Database](https://cwe.mitre.org/)
