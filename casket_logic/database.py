import os
import json

# Define where the file lives
DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "void.dat")

def ensure_data_dir():
    """Creates the data directory if it doesn't exist."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def load_vault():
    """
    Reads the encrypted file from the disk.
    Returns: The data dict or None if file doesn't exist.
    """
    if not os.path.exists(DATA_FILE):
        return None
    
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        # If the file is corrupted or unreadable
        return None

def save_vault(header, vault_blob):
    """
    Saves the header (keys) and the vault (passwords) to disk.
    """
    ensure_data_dir()
    
    data = {
        "header": header,     # Contains Hash + Encrypted TOTP Secret
        "vault": vault_blob   # Contains the actual passwords
    }
    
    with open(DATA_FILE, 'w') as f:
        # indent=4 makes it readable if you open it in notepad (though it's encrypted)
        json.dump(data, f, indent=4)