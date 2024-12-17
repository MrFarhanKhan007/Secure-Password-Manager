from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, User, Password  # Import db and models
from utils.encryption import encrypt_password, decrypt_password
import pyotp
import os
from utils.mfa import generate_qr_code

# Initialize the Flask app
app = Flask(__name__)

# Configuration for the database
app.secret_key = os.urandom(24)  # Secure session key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:!roommate123@localhost/password_manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking for performance

# Initialize SQLAlchemy with the Flask app
db.init_app(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['password']  # Get the password from the form

        # Encrypt the master password
        encrypted_password = encrypt_password(master_password)
        
        # Generate a new TOTP secret
        totp_secret = pyotp.random_base32()
        
        # Create a new user with the encrypted password and TOTP secret
        new_user = User(username=username, master_password=encrypted_password, totp_secret=totp_secret)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['password']

        print(f"Attempting to log in with username: {username}")  # Debugging log

        # Check user in the database
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("User not found!", "danger")
            print("User not found")  # Debugging log
            return redirect(url_for('login'))

        # Validate password
        decrypted_password = decrypt_password(user.master_password)
        if master_password != decrypted_password:
            flash("Invalid credentials!", "danger")
            print("Invalid password")  # Debugging log
            return redirect(url_for('login'))

        # Store user info in session for MFA
        session['user_id'] = user.id
        session['mfa_secret'] = user.totp_secret
        session['username'] = user.username
        print("Redirecting to MFA")  # Debugging log
        return redirect(url_for('mfa'))

    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch stored passwords for the logged-in user
    user_id = session['user_id']
    saved_passwords = Password.query.filter_by(user_id=user_id).all()

    # Decrypt passwords to display them
    passwords = []
    for pwd in saved_passwords:
        decrypted_password = decrypt_password(pwd.password)
        passwords.append({
            'site_name': pwd.site_name,
            'username': pwd.username,
            'decrypted_password': decrypted_password
        })

    return render_template('dashboard.html', passwords=passwords)


@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'mfa_secret' not in session:
        return redirect(url_for('login'))

    # Generate QR code for the TOTP secret
    if request.method == 'GET':
        qr_image = generate_qr_code(session['username'], session['mfa_secret'])  # Use the secret
        return render_template('mfa.html', qr_image=qr_image)

    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(session['mfa_secret'])
        if totp.verify(otp):  # Verify the OTP
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP! Please try again.", "danger")
            return redirect(url_for('mfa'))

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    site_name = request.form['site_name']
    username = request.form['username']
    password = request.form['password']

    # Encrypt the password
    encrypted_password = encrypt_password(password)

    # Save to the database
    new_password = Password(user_id=session['user_id'], site_name=site_name, username=username, password=encrypted_password)
    db.session.add(new_password)
    db.session.commit()

    flash("Password added successfully!", "success")
    return redirect(url_for('dashboard'))

from flask import make_response

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Initialize database (only once, if necessary)
    app.run(debug=True)
