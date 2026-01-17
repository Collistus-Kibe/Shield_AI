# File: core/ai_debrief.py
import datetime
import os

def _translate_reason(reason):
    """
    Simulates an AI analyst translating technical jargon into a
    human-readable explanation for a debriefing report.
    """
    reason_lower = reason.lower()
    
    if "entropy" in reason_lower:
        return f"• The file's name appears to be intentionally scrambled or obfuscated ({reason}). This is a common tactic to avoid detection by simple signature-based scanners."
    
    if "not on trusted lists" in reason_lower:
        return "• This application was not recognized as safe by either your local trust list or the Shield AI Global Intelligence database. Unrecognized software is treated as suspicious by default."
    
    if "launched by unusual parent" in reason_lower:
        parent = reason.split(':')[-1].strip()
        return f"• It was started by an unexpected program ('{parent}'). Malicious scripts (e.g., in an email or document) often launch hostile processes in this way."
    
    if "blacklist" in reason_lower:
        return "• CRITICAL FINDING: This file is a confirmed, known-malicious entity identified by the Shield AI Global Intelligence network. Its signature is on our global blacklist."
    
    if "high-risk process run by non-admin" in reason_lower:
        return f"• A high-risk system tool was executed by a low-privilege user ({reason.split('(')[-1][:-1]}). This is highly irregular and often signals an attempt to bypass security or escalate privileges."
    
    if "no user context" in reason_lower:
        return "• The process was running without a clear user owner ('no user context'). This behavior is common for system-level malware and rootkits attempting to hide."
    
    # Default fallback for any other reason
    return f"• {reason}"

def generate_debriefing(threat_details):
    """
    Uses AI-driven heuristics (simulated) to generate a human-readable
    threat debriefing report from a quarantine manifest entry.
    """
    if not threat_details:
        return "ERROR: No threat data provided. Cannot generate report. Please refresh the quarantine list and try again."

    try:
        # --- Extract Data ---
        name = threat_details.get('threat_name', 'Unknown Threat')
        level = threat_details.get('threat_level', 'N/A')
        score = threat_details.get('threat_score', 'N/A')
        path = threat_details.get('original_path', 'N/A')
        date_str = threat_details.get('date_quarantined', 'N/A')
        reasons = threat_details.get('reasons', ['No specific reasons logged.'])

        # --- Format Date ---
        try:
            dt = datetime.datetime.fromisoformat(date_str)
            nice_date = dt.strftime("%Y-%m-%d at %H:%M:%S")
        except (ValueError, TypeError):
            nice_date = str(date_str)

        # --- Build Report Sections ---
        report = []
        report.append(f"AI DEBRIEFING: {os.path.basename(path)}\n")
        report.append(f"Threat Level: {level} (Score: {score})\n")
        report.append(f"Neutralized On: {nice_date}\n")
        report.append(f"Original Location: {path}\n")
        report.append("="*50 + "\n")

        # --- Executive Summary ---
        report.append("EXECUTIVE SUMMARY:\n")
        if level == "CRITICAL":
            summary = f"Shield AI neutralized '{name}', a CRITICAL-level threat. This file was positively identified as malicious and posed an immediate danger to system security. Quarantine action was essential."
        elif level == "HIGH":
            summary = f"Shield AI neutralized '{name}', a HIGH-level threat. This file exhibited multiple high-risk behaviors consistent with malware, such as obfuscation or an unusual launch process."
        elif level == "MEDIUM":
            summary = f"Shield AI neutralized '{name}', a MEDIUM-level threat. This file exhibited suspicious characteristics that triggered a precautionary quarantine to protect system integrity."
        else:
            summary = f"Shield AI neutralized '{name}'. This file was flagged for suspicious indicators. The quarantine action was a precautionary measure."
        report.append(summary + "\n\n")

        # --- Analysis & Key Indicators ---
        report.append("ANALYSIS & KEY INDICATORS:\n")
        
        translated_reasons = [_translate_reason(r) for r in reasons if "on trusted list" not in r.lower()]
        if not translated_reasons:
            report.append("• No specific threat indicators were logged. This may have been a manual quarantine action.")
        else:
            report.extend(translated_reasons)
        
        report.append("\n\n")
        
        # --- Recommended Action ---
        report.append("RECOMMENDED ACTION:\n")
        report.append("No immediate action is required by the operator. The threat has been successfully contained in the quarantine directory.\n")
        report.append("You may now review the file's details and choose to permanently DELETE it or, if you are 100% certain it is safe, RESTORE it.")

        return "\n".join(report)

    except Exception as e:
        return f"AI Debriefer Error: Failed to parse threat details. Details: {e}"