
# Communication_LTD Project

This project demonstrates secure and vulnerable implementations of a web application for a fictional company, **Communication_LTD**. The system handles employee management, customer additions, and administrative tasks, showcasing security best practices alongside common vulnerabilities.

## Project Overview

The project consists of two versions:
1. **Secure Version**: Implements protections against SQL injection and XSS.
2. **Vulnerable Version**: Contains intentionally insecure code for demonstration purposes.

---

## Features

### Common Features in Both Versions
- **User Authentication**: Secure login, logout, and registration.
- **Admin Dashboard**: Features for managing users and customers.
- **Password Recovery**: Forgot password and reset password flows.
- **Search and Add Customers**: Search users and add customers via the admin interface.
- **Email Integration**: Password recovery and token verification using Flask-Mail.

### Security Features (Secure Version)
- **XSS Protection**: Uses Flask's `escape` function to sanitize user input.
- **SQL Injection Mitigation**: Implements parameterized SQL queries instead of concatenated strings.
- **Input Validation**: Ensures proper input handling across routes.

### Vulnerabilities (Vulnerable Version)
- **SQL Injection**: Uses raw, concatenated SQL queries, allowing injection attacks.
- **XSS Risks**: Direct rendering of unsanitized user input in HTML templates.


<img width="533" alt="[Screenshot 2024-12-16 134320" src="https://github.com/user-attachments/assets/6d192ac8-4e66-4fa1-95f9-428c0fdedfef">
<img width="533" alt="[Screenshot 2024-12-16 134337" src="https://github.com/user-attachments/assets/49f5c272-ee53-431e-ad5b-bf7277815e5c">
<img width="533" alt="[Screenshot 2024-12-16 134304" src="https://github.com/user-attachments/assets/e442cda9-46df-4e41-9374-20aa77755bf8">

---

## Setup Instructions

### Prerequisites
- Python 3.9+
- Flask
- SQLite (pre-configured `.db` file included for quick setup)

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Communication_LTD
   ```

2. Install dependencies for the secure or vulnerable version:
   ```bash
   pip install -r secure_version/requirements.txt  # For secure version
   pip install -r vulnerable_version/requirements.txt  # For vulnerable version
   pip install Flask-Mail
   ```
   
3. Configure Flask-Mail
  Update the email configuration in `config.py`:
  ```python
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-email@example.com'
    MAIL_PASSWORD = 'your-email-password'
 ```

5. Set up the database (optional):
   - Secure version: Uses `secure.db`.
   - Vulnerable version: Uses `vulnerable.db`.

6. Run the application:
   ```bash
   python secure_version/app.py  # For secure version
   python vulnerable_version/app.py  # For vulnerable version
   ```

---

## How to Test Vulnerabilities

### SQL Injection
- **Example Route:** `/login`
- **Exploit:** Enter `' OR '1'='1` in the username or password field in the vulnerable version.

### XSS
- **Example Route:** `/register`
- **Exploit:** Input `<script>alert('XSS')</script>` as a name or other field in the vulnerable version.

---

## File Structure

```
Communication_LTD/
├── secure_version/
│   ├── app.py
│   ├── add_customers.py
│   ├── config.py
│   ├── requirements.txt
│   ├── database/
│   │   ├── schema.sql
│   │   └── secure.db
│   ├── templates/
│   └── static/
├── vulnerable_version/
│   ├── app.py
│   ├── config.py
│   ├── requirements.txt
│   ├── database/
│   │   ├── schema.sql
│   │   └── vulnerable.db
│   ├── templates/
│   └── static/
```

---

## Contributors

- [Sahar Yehezkel]([https://github.com/your-profile](https://github.com/SaharYehezkel))

---
