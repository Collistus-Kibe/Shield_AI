import datetime

def format_cef(log_level, event_name, message, details=""):
    """
    Formats a log message into the Common Event Format (CEF).
    
    CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    version = "0"
    vendor = "ShieldAI"
    product = "ErevosCore"
    device_version = "2.0"
    
    # Map our internal log levels to CEF severity standard (0-10 integer)
    severity_map = {
        'INFO': '3',
        'WARN': '6',      # Using WARN for GUI alerts
        'CRITICAL': '9'
    }
    severity = severity_map.get(log_level, "1")

    # The CEF standard requires escaping certain characters in the extension field.
    # For our prototype, we will keep it simple.
    
    header = f"CEF:{version}|{vendor}|{product}|{device_version}|{event_name}|{event_name}|{severity}|"
    extension = f"msg={message} {details}"

    return header + extension