import json

def load_directory(log):
    """Loads the corporate directory from the JSON file."""
    try:
        with open('corporate_directory.json', 'r') as f:
            log.info("Corporate directory loaded successfully.")
            return json.load(f)
    except FileNotFoundError:
        log.warning("corporate_directory.json not found. Running without user context analysis.")
        return None
    except json.JSONDecodeError:
        log.error("Failed to decode corporate_directory.json. Check for syntax errors.")
        return None

def get_user_privilege_level(username, directory):
    """Finds a user's privilege level from the directory."""
    if not directory or not username:
        return 3 # Default to a low-medium privilege if directory/user is unknown

    user_roles = directory.get('user_roles', {})
    role_permissions = directory.get('role_permissions', {})
    
    user_role = user_roles.get(username, "Standard_User") # Default to Standard_User
    privilege_level = role_permissions.get(user_role, {}).get('privilege_level', 3)
    
    return privilege_level

