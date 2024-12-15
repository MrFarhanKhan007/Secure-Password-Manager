import pyotp
import qrcode
import base64
from io import BytesIO

def generate_otp(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_otp(secret: str, otp: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

def generate_qr_code(username: str, secret: str) -> str:
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="PasswordManager")
    qr = qrcode.make(uri)
    
    # Convert QR code to a byte stream and encode it in base64
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return img_str  # Return the base64 string of the image
