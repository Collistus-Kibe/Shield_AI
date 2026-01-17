import re
from urllib.parse import urlparse

def analyze_url(url):
    """
    Performs a heuristic analysis of a URL to detect signs of phishing or malware.
    """
    score = 0
    reasons = []

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            raise ValueError("Invalid URL provided")

        # Heuristic 1: IP Address in Hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 40
            reasons.append("URL uses an IP address instead of a domain name.")

        # Heuristic 2: Presence of '@' symbol in URL (common phishing trick)
        if '@' in url.split('/')[2]:
            score += 30
            reasons.append("URL contains '@' symbol in the authority part, which can obscure the real domain.")

        # Heuristic 3: Number of subdomains
        if hostname.count('.') > 3:
            score += 25
            reasons.append(f"URL has an unusually high number of subdomains ({hostname.count('.')}).")

        # Heuristic 4: Suspicious Top-Level Domains (TLDs)
        suspicious_tlds = ['.xyz', '.top', '.buzz', '.tk', '.link', '.club']
        if any(tld for tld in suspicious_tlds if hostname.endswith(tld)):
            score += 35
            reasons.append("URL uses a TLD commonly associated with spam or malware.")

        # Heuristic 5: Presence of sensitive keywords in the path or subdomain
        sensitive_keywords = ['login', 'verify', 'account', 'secure', 'password', 'update']
        if any(keyword in url.lower() for keyword in sensitive_keywords):
            score += 20
            reasons.append("URL contains sensitive keywords, often used in phishing attempts.")

    except Exception as e:
        return {'score': -1, 'reasons': [f"Error analyzing URL: {e}"]}

    if not reasons:
        reasons.append("URL appears to be safe based on heuristics.")
        
    return {'score': score, 'reasons': reasons}