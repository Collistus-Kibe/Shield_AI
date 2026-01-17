import sys
import os
import winreg as reg

def add_to_startup():
    """
    Adds the Shield AI GUI to the current user's startup programs.
    """
    # Get the absolute path to the venv's pythonw.exe
    # pythonw.exe is used to run GUI applications without a console window
    python_exe = os.path.join(sys.prefix, 'pythonw.exe')
    
    # Get the absolute path to our GUI script
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'shield_gui.py'))
    
    # The command to execute
    command = f'"{python_exe}" "{script_path}"'
    
    # The registry key for current user startup programs
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    try:
        # Open the registry key
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        
        # Set the value. We name it "ShieldAI"
        reg.SetValueEx(key, "ShieldAI", 0, reg.REG_SZ, command)
        
        # Close the key
        reg.CloseKey(key)
        
        print("✅ Shield AI has been successfully added to startup.")
        print("It will now launch automatically when you log in.")
        
    except Exception as e:
        print(f"⛔ ERROR: Could not add Shield AI to startup. Administrator rights may be required.")
        print(f"   Details: {e}")

def remove_from_startup():
    """
    Removes Shield AI from the current user's startup programs.
    """
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "ShieldAI"
    
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE)
        reg.DeleteValue(key, value_name)
        reg.CloseKey(key)
        print("✅ Shield AI has been successfully removed from startup.")
        
    except FileNotFoundError:
        print("INFO: Shield AI was not found in startup programs.")
    except Exception as e:
        print(f"⛔ ERROR: Could not remove Shield AI from startup.")
        print(f"   Details: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == 'install':
            add_to_startup()
        elif sys.argv[1] == 'uninstall':
            remove_from_startup()
        else:
            print(f"Unknown command: {sys.argv[1]}")
            print("Usage: python setup.py [install|uninstall]")
    else:
        print("Usage: python setup.py [install|uninstall]")