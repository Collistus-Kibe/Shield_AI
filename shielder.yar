/*
    SHIELD AI - CORTEX RULES V1.0
    Integrated YARA Definitions for High-Speed Scanning
*/

rule Detect_WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry variants"
        threat_level = "CRITICAL"
    strings:
        $s1 = "Ooops, your files have been encrypted!" ascii
        $s2 = "WNcry@2ol7" ascii
        $s3 = "msg/m_bulgarian.wnry" ascii
    condition:
        any of them
}

rule Detect_Generic_Keylogger {
    meta:
        description = "Detects common Keylogging behavior"
        threat_level = "HIGH"
    strings:
        $k1 = "SetWindowsHookEx" ascii
        $k2 = "GetAsyncKeyState" ascii
        $k3 = "MapVirtualKey" ascii
        $k4 = "[CAPSLOCK]" ascii
    condition:
        ($k1 and $k2 and $k3) or ($k4)
}

rule Detect_Reverse_Shell {
    meta:
        description = "Detects Python/Bash Reverse Shells"
        threat_level = "HIGH"
    strings:
        $p1 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" ascii
        $p2 = "subprocess.call([\"/bin/sh\", \"-i\"])" ascii
        $p3 = "os.dup2(s.fileno(),0)" ascii
    condition:
        2 of them
}

rule Detect_Suspicious_Powershell {
    meta:
        description = "Detects Obfuscated PowerShell Attacks"
        threat_level = "MEDIUM"
    strings:
        $ps1 = "-Enc" nocase
        $ps2 = "-WindowStyle Hidden" nocase
        $ps3 = "IEX ((new-object net.webclient).downloadstring" nocase
    condition:
        any of them
}

rule Detect_Embedded_EXE {
    meta:
        description = "Detects executables hidden inside other files"
        threat_level = "MEDIUM"
    strings:
        $mz = "MZ" // The magic header for Windows EXEs
    condition:
        $mz at 0
}