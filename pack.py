# This is a new file you will create.
# File: shield_ai/pack.py

import os

# --- Configuration ---
# All the critical files we need to remember
FILES_TO_PACK = [
    # Core Agent Files
    'shield_gui.py',
    'core/shield_backend.py',
    'core/actions.py',
    'core/monitoring.py',
    'core/network_monitor.py',
    'core/policy_manager.py',
    'core/config_manager.py',
    'core/pin_auth.py',
    'core/static_analyzer.py',
    'core/web_guard.py',
    'core/directory_services.py',
    'core/firewall_manager.py',
    'core/debriefing_ai.py',
    'core/biometric_auth.py', # We keep this for history, even if disabled
    'utils/gui_logger.py',
    'utils/helpers.py',
    'utils/cef_formatter.py',
    
    # Configuration Files
    'config.ini',
    'policy.ini',
    'corporate_directory.json',
    'global_intelligence.json',
    'payload.py',
    'requirements.txt',
    
    # Hive Server Files
    '../shield_hive/hive_server.py'
]

OUTPUT_FILE = 'PROJECT_STATE.md'
# --- End Configuration ---

def pack_project():
    print(f"📦 Starting project packager...")
    
    # Use a relative path for the output file
    output_path = os.path.join(os.path.dirname(__file__), OUTPUT_FILE)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"# SHIELD AI: PROJECT STATE SNAPSHOT\n")
        f.write(f"# Generated on: {datetime.datetime.now().isoformat()}\n\n")
        
        for file_path in FILES_TO_PACK:
            # Build the absolute path to the file
            abs_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), file_path))
            
            if not os.path.exists(abs_file_path):
                print(f"⚠️  Warning: File not found, skipping: {file_path}")
                continue
                
            print(f"   -> Packing: {file_path}")
            
            f.write(f"\n\n\n")
            f.write("="*80 + "\n")
            f.write(f"## 📦 {file_path}\n")
            f.write("="*80 + "\n")
            
            # Read the file content
            try:
                with open(abs_file_path, 'r', encoding='utf-8') as content_file:
                    content = content_file.read()
                
                # Use markdown code block to store the content
                file_extension = os.path.splitext(file_path)[1].lstrip('.')
                if not file_extension:
                    file_extension = 'ini' # Default for files with no extension
                    
                f.write(f"```{file_extension}\n")
                f.write(content)
                f.write(f"\n```\n")
                
            except Exception as e:
                f.write(f"!!! Error reading file: {e} !!!\n")

    print(f"\n✅  SUCCESS! Project state has been packed into: {OUTPUT_FILE}")

if __name__ == "__main__":
    import datetime
    pack_project()