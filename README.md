# Password Manager with Multi-Factor Authentication (MFA) 🔐

## Description 📜

This project is a **Password Manager** application with **Multi-Factor Authentication (MFA)** to securely store and manage your passwords. The project includes:

- **Encrypted Password Storage** 🛡️
- **Password Decryption** 🔓
- **Multi-Factor Authentication (MFA)** through a **QR Code** and **Authenticator App** 📱
- **Dashboard to Display Stored Passwords** 💻

## Features 🌟

- **Encrypted Passwords**: All user passwords are encrypted before storage in the database using strong encryption methods to ensure security.
  
- **Decryption**: The passwords are decrypted on-demand when the user wants to view them.

- **Multi-Factor Authentication (MFA)**: Users can scan a QR code with an authenticator app (like Google Authenticator or Authy) to add an extra layer of security to their account.

- **Password Management Dashboard**: Once logged in with MFA, users can view their saved passwords in a clean, organized table format on the dashboard.

## Technologies Used ⚙️

- **Frontend**: HTML, CSS
- **Backend**: Python (Flask for API)
- **Database**: MySQL 💾
- **Encryption**: AES for password encryption and decryption 🔐
- **MFA**: QR Code generation with `pyotp` and Google Authenticator 📲

## Installation & Setup 🚀

### Prerequisites ⚙️

1. Install **Python** (preferably 3.8 or higher) on your machine.
2. Install **MySQL** (you can use [MySQL Community Server](https://dev.mysql.com/downloads/installer/) for your platform).
3. Ensure **pip** is installed to manage Python packages.

### Steps to Clone and Run the Project 🖥️

1. **Clone the Repository**:

   Open your terminal and run the following command to clone the repository to your local machine:

   ```bash
     git clone https://github.com/yourusername/password-manager.git
     cd password-manager
     python3 -m venv venv
     source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
     pip install -r requirements.txt
    ```

    Requirements.txt may have the following requirements:

    ```txt
      flask
      flask-sqlalchemy
      flask-wtf
      pycryptodome
      pyotp
      qrcode
    ```
    SQL Commands to setup the MySQL Database in your SQL command line client:
     (Install MYSQL full client from this website first- https://dev.mysql.com/downloads/installer/)
    ```sql

    CREATE DATABASE password_manager;

    CREATE TABLE passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    encrypted_password TEXT NOT NULL,
    site_name VARCHAR(255) NOT NULL
    );

    CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    mfa_secret VARCHAR(255) NOT NULL
    );

    ```
  
3. **Using the Application**: 💻
   
    **Sign Up / Log In**:
    
    - Users need to sign up by providing a username and password.
    
    - Once registered, the user will be prompted to enable MFA (Multi-Factor Authentication) by scanning the QR code generated by the app using an authenticator app.
  
    **Storing Passwords**:

    - After successful login with MFA, users can add and store passwords associated with various sites in the application.
    
    - Passwords are encrypted before being stored in the database.
  
    **Viewing Passwords**:
  
    - Users can view stored passwords after logging in, where the password will be decrypted on-demand when the user requests to view it.
    
    - The saved passwords are displayed in a table on the dashboard with details like the site name and username.
  
    **How to Use MFA** 🔑
    
    - Upon registration, a QR Code will be shown, which you need to scan with an authenticator app (such as Google Authenticator or Authy).
   
    - After scanning the QR code, the app will generate a time-based OTP (One-Time Password) every 30 seconds.
      
    - Enter the OTP into the field on the app and click Verify to complete the MFA process.
    
    - On each login, the user will be prompted for the OTP to verify identity.

  ## Screenshots 📸

  Here’s a preview of what the app looks like:
  ![Untitled design](https://github.com/user-attachments/assets/4489cc79-c8a5-4e70-9118-fcb79858f33f)


  ## Contributing 🤝

  We welcome contributions to improve the functionality and security of the Password Manager. If you have ideas, bug fixes, or other improvements, please fork the repository and submit a pull request. Ensure that your changes are properly tested and follow the coding standards used in the project.

  ## License 📜

  This project is licensed under the MIT License - see the LICENSE file for details.

  ## Acknowledgments 🙏

  - Thanks to Flask for the web framework.

  - Thanks to pyotp for implementing OTP generation.
  
  - Thanks to MySQL for the database engine

  ## Sample video attached below: 
  - First part of the video shows the website
    
  - Second part of the video shows how to setup the MySQL database from the MySQL CMD Line(which you will get from the MySQL toolkit)

https://github.com/user-attachments/assets/556fd9cf-9158-4e66-aa40-e0eda739924e
