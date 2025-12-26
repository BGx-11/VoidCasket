import pyotp
import qrcode
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from rich.console import Console

# We use Rich for printing the QR code nicely in the terminal
console = Console()
ph = PasswordHasher()

def generate_totp_secret():
    """Generates a random 32-character Base32 secret key."""
    return pyotp.random_base32()

def get_totp_uri(secret, username="User", issuer="VoidCasket"):
    """Creates the provisioning URI for Google Authenticator."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

def display_qr_code(secret):
    """
    Generates a QR code in the terminal for the user to scan.
    """
    uri = get_totp_uri(secret)
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii(invert=True)
    
    console.print(f"[bold yellow]Secret Key (Manual Entry):[/bold yellow] {secret}")
    console.print("[dim]Scan this QR code with Google Authenticator or Authy.[/dim]")

def verify_totp(secret, user_input_code):
    """
    Checks if the 6-digit code matches the secret.
    Returns True/False.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(user_input_code)

def hash_master_password(password):
    """
    Hashes the password using Argon2 (Memory-hard hashing).
    This is for VERIFYING the password, not for encryption keys.
    """
    return ph.hash(password)

def verify_master_password(stored_hash, input_password):
    """
    Verifies the input password against the stored hash.
    """
    try:
        ph.verify(stored_hash, input_password)
        return True
    except VerifyMismatchError:
        return False