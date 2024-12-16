# Secure Version - app.py
import hashlib
import re
import os
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy import JSON
from markupsafe import escape
from flask import session

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    password_history = db.Column(JSON, nullable=True, default=[])
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(200), nullable=True)

class Sector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sectorName = db.Column(db.String(80), unique=True, nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(50), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    sector_id = db.Column(db.Integer, db.ForeignKey('sector.id'), nullable=False) 
    sector = db.relationship('Sector', backref='users', lazy=True)

# Create all database tables
with app.app_context():
    db.create_all()

# Initialize Flask-Mail
mail = Mail(app)

#
##
### Methods
##
#

def validate_password(password):
    if len(password) < app.config['PASSWORD_MIN_LENGTH']:
        return False, f'Password must be at least {app.config["PASSWORD_MIN_LENGTH"]} characters long.'
    if not re.match(app.config['PASSWORD_COMPLEXITY'], password):
        return False, 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
    for word in app.config['PASSWORD_DICTIONARY']:
        if word in password.lower():
            return False, 'Password cannot contain common dictionary words.'
    return True, ''

def is_password_in_history(user, new_hashed_password):
    if not user.password_history:
        return False
    return new_hashed_password in user.password_history

def is_malicious_input(input_value):
    """ Detects if the input contains SQL Injection or XSS patterns """
    dangerous_patterns = [
        # SQL Injection patterns
        r"(?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|(\b(select|insert|delete|update|drop|alter|create|table|from|where|union|join|or)\b)",
        r"(?:' OR '[^']+'='[^']+')",   # SQLi pattern for string comparison
        r"(?:' OR [0-9]+=+[0-9]+)",    # SQLi pattern for numeric comparison
        
        # XSS patterns
        r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",  # Script tags
        r"[\w\W]*<[\s\S]*on[\w]*=[\w\s]*",  # Inline event handlers in HTML (e.g., onload, onclick)
        r"javascript:",  # JavaScript protocol handler

        # General dangerous characters that may indicate an attack
        r"[<>\"'&]",  # Characters typically involved in XSS
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, input_value, re.IGNORECASE):
            print(f"Malicious pattern detected in input: {input_value}")  # Debugging log
            return True
    return False

#
##
### Routes
##
#

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        email = escape(request.form['email'])
        password = escape(request.form['password'])
        confirm_password = escape(request.form['confirm-password'])

        # Detect malicious input for SQL Injection or XSS
        if is_malicious_input(username) or is_malicious_input(email) or is_malicious_input(password):
            flash('Invalid input detected. Please avoid using special characters.', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            session.clear()
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        # Validate password strength
        valid, message = validate_password(password)
        if not valid:
            session.clear()
            flash(message, 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            session.clear()
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        # Hash the password using SHA-1
        sha1 = hashlib.sha1()
        sha1.update(password.encode('utf-8'))  # Convert the password to bytes
        hashed_password = sha1.hexdigest()     # Get the SHA-1 hash in hexadecimal

        # Add the hashed password to the password history
        password_history = [hashed_password]

        # Create a new user and save to the database
        new_user = User(username=username, email=email, password=hashed_password, password_history=password_history)

        # Add the new user to the database
        db.session.add(new_user)
        try:
            db.session.commit()  # Save to the database
            session.clear()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Database error: {e}")  # Debugging
            session.clear()
            flash('An error occurred while trying to register. Please try again.', 'danger')
            return redirect(url_for('register'))

    sectors = Sector.query.all()
    return render_template('register.html', sectors=sectors)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Sanitize and escape user inputs
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        # Detect malicious input for SQL Injection or XSS
        if is_malicious_input(username) or is_malicious_input(password):
            flash('Invalid input detected. Please avoid using special characters.', 'danger')
            return redirect(url_for('login'))

        # Check if both fields are filled
        if not username or not password:
            flash('Both username and password are required.', 'danger')
            return redirect(url_for('login'))

        # Check user in database
        user = User.query.filter_by(username=username).first()

        if user:
            # Check if the account is locked due to too many failed attempts
            if user.is_locked:
                flash('Your account is locked due to too many failed login attempts.', 'danger')
                return redirect(url_for('login'))

            # Hash the provided password to compare with stored hash
            sha1 = hashlib.sha1()
            sha1.update(password.encode('utf-8'))
            hashed_password = sha1.hexdigest()

            # If password matches
            if user.password == hashed_password:
                # Reset failed attempts upon successful login
                user.failed_attempts = 0
                db.session.commit()

                # Store the logged-in user in the session
                session['username'] = user.username

                return redirect(url_for('admin_dashboard'))
            else:
                # Increment failed attempts if the password is incorrect
                user.failed_attempts += 1

                # Lock account if login attempts exceed the limit
                if user.failed_attempts >= app.config['LOGIN_ATTEMPTS_LIMIT']:
                    user.is_locked = True
                    flash('Your account has been locked due to too many failed login attempts.', 'danger')
                else:
                    flash('Invalid username or password.', 'danger')

                db.session.commit()
                return redirect(url_for('login'))

        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin-dashboard')
def admin_dashboard():
# Fetch customers grouped by sector
    customers_by_sector = {}
    sectors = Sector.query.all()  # Retrieve all sectors

    for sector in sectors:
        # Fetch customers in each sector and group them by sector name
        customers_in_sector = Customer.query.filter_by(sector_id=sector.id).all()
        customers_by_sector[sector.sectorName] = customers_in_sector

    return render_template('admin.html', customers_by_sector=customers_by_sector, sectors=sectors)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    session.clear()
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a random token
            random_token = os.urandom(16).hex()

            # Hash the token using SHA-1
            sha1 = hashlib.sha1()
            sha1.update(random_token.encode('utf-8'))
            hashed_token = sha1.hexdigest()

            # Store the hashed token in the user's record (for later verification)
            user.reset_token = hashed_token
            db.session.commit()

            # Send the unhashed token to the user's email
            try:
                msg = Message('Password Reset Token',
                              recipients=[email],
                              body=f'Your password reset token is: {random_token}')
                mail.send(msg)
                flash('A password reset token has been sent to your email.', 'success')

                # Redirect to token verification page
                return redirect(url_for('verify_token'))
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Failed to send the email. Please try again later.', 'danger')
        else:
            flash('No account found with that email.', 'danger')

    return render_template('forgotPassword.html')

@app.route('/verify-token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']

        # Hash the provided token using SHA-1
        sha1 = hashlib.sha1()
        sha1.update(token.encode('utf-8'))
        hashed_token = sha1.hexdigest()

        # Find the user by email
        user = User.query.filter_by(email=email).first()

        # Check if the hashed token matches
        if user and user.reset_token == hashed_token:
            flash('Token verified! Please reset your password.', 'success')
            return redirect(url_for('reset_password', user_id=user.id))
        else:
            flash('Invalid token or email. Please try again.', 'danger')
            return redirect(url_for('verify_token'))

    return render_template('verifyToken.html')

@app.route('/reset-password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Get the new password and confirm password
        new_password = escape(request.form['new_password'])
        confirm_password = escape(request.form['confirm_password'])

        # Detect malicious input for SQL Injection or XSS
        if is_malicious_input(new_password) or is_malicious_input(confirm_password):
            flash('Invalid input detected. Please avoid using special characters.', 'danger')
            return redirect(url_for('reset_password', user_id=user_id))

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', user_id=user_id))

        # Validate password strength
        valid, message = validate_password(new_password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('reset_password', user_id=user_id))

        # Hash the new password using SHA-1
        sha1 = hashlib.sha1()
        sha1.update(new_password.encode('utf-8'))
        new_hashed_password = sha1.hexdigest()

        # Check if the new password is in the password history
        if user.password_history and new_hashed_password in user.password_history:
            flash('You cannot reuse a recently used password.', 'danger')
            return redirect(url_for('reset_password', user_id=user_id))

        # Update the password history (keep only the last 3 passwords)
        if not user.password_history:
            user.password_history = []
        else:
            user.password_history = list(user.password_history)  # Ensure it's a mutable list

        if len(user.password_history) >= 3:
            user.password_history.pop(0)  # Remove the oldest password

        # Add the current (old) password to the password history
        user.password_history.append(new_hashed_password)

        # Update the user's password to the new hashed password
        user.password = new_hashed_password
        user.reset_token = None  # Clear the reset token
        db.session.commit()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('resetPassword.html')

@app.route('/admin-search', methods=['GET'])
def admin_search():
    search_query = escape(request.args.get('search', ''))

    # Detect malicious input for SQL Injection or XSS
    if is_malicious_input(search_query):
        flash('Invalid input detected. Please avoid using special characters.', 'danger')
        return redirect(url_for('admin_dashboard'))  # Redirect back to admin dashboard
    
    # Perform the search if there is a query
    if search_query:
        customers = Customer.query.filter(
            (Customer.full_name.ilike(f'%{search_query}%')) | 
            (Customer.email.ilike(f'%{search_query}%'))
        ).all()
    else:
        customers = []  # No search query, no customers found

    # Fetch customers grouped by sector for the main dashboard
    customers_by_sector = {}
    sectors = Sector.query.all()
    for sector in sectors:
        customers_by_sector[sector.sectorName] = Customer.query.filter_by(sector_id=sector.id).all()

    # Render the admin dashboard template, passing both search results and customers by sector
    return render_template('admin.html', customers=customers, customers_by_sector=customers_by_sector, sectors=sectors, search_query=search_query)

@app.route('/admin-add-customer', methods=['POST'])
def admin_add_customer():
    # Get data from the form
    full_name = escape(request.form['full_name']) 
    email = escape(request.form['email'])
    sector_id = request.form['sector_id']

    # Detect malicious input for SQL Injection or XSS
    if is_malicious_input(full_name) or is_malicious_input(email):
        flash('Invalid input detected. Please avoid using special characters.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Check if email already exists in the Customer table
    customer_exists = Customer.query.filter_by(email=email).first()
    if customer_exists:
        flash('Customer with this email already exists.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Create new customer
    new_customer = Customer(full_name=full_name, email=email, sector_id=sector_id)

    # Add the new customer to the database
    db.session.add(new_customer)
    db.session.commit()

    flash('New customer added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)