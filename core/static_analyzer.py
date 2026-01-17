import re
from utils.helpers import calculate_entropy

def analyze_script_content(file_path, log):
    """
    Performs static analysis on a script file to identify malicious characteristics.
    """
    log.info(f"STATIC_ANALYSIS: Initiating for '{file_path}'...")
    report = {
        'score': 0,
        'reasons': []
    }
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # 1. Check for suspicious keywords and imports (e.g., eval, exec)
        suspicious_keywords = re.findall(r'(eval|exec|subprocess|base64\.b64decode|requests\.post)', content)
        if suspicious_keywords:
            hits = list(set(suspicious_keywords)) # Get unique hits
            report['score'] += 25 * len(hits)
            report['reasons'].append(f"Suspicious keywords found: {hits}")

        # 2. Check for suspicious string patterns (IPs, sensitive paths)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        sensitive_paths = r'(/etc/passwd|~/\.ssh/|C:\\Windows\\System32)'
        if re.search(ip_pattern, content):
            report['score'] += 20
            report['reasons'].append("IP address found in string literal.")
        if re.search(sensitive_paths, content):
            report['score'] += 30
            report['reasons'].append("Reference to sensitive system path found.")
            
        # 3. Check for high entropy (obfuscation/packed code)
        entropy = calculate_entropy(content)
        if entropy > 4.5: # Entropy threshold is higher for a whole file
            report['score'] += 35
            report['reasons'].append(f"High content entropy ({entropy:.2f}) suggests obfuscation.")
        
        # Log the final report
        if report['score'] > 0:
            log.warning("--- [ START STATIC ANALYSIS REPORT ] ---")
            log.warning(f"File: {os.path.basename(file_path)}")
            log.warning(f"Final Threat Score: {report['score']}")
            log.warning("Reasons:")
            for reason in report['reasons']:
                log.warning(f"  - {reason}")
            log.warning("--- [ END STATIC ANALYSIS REPORT ] ---")
        else:
            log.info(f"STATIC_ANALYSIS: '{file_path}' appears clean. Score: 0.")

    except FileNotFoundError:
        log.error(f"STATIC_ANALYSIS_FAILED: File not found at '{file_path}'.")
    except Exception as e:
        log.critical(f"STATIC_ANALYSIS_FAILED: An unexpected error occurred. {e}")