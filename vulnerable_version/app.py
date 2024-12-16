# Vulnerable Version - app.py
import hashlib
import os
import re
from flask import Flask, request, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from sqlalchemy import JSON
from markupsafe import escape
from flask import session
from sqlalchemy import text 
import json

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable.db'
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
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Check if passwords match for normal registration
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

        # Detect SQL Injection attempt (for demo purposes)
        if "' OR '" in username or "'--" in username or "UNION" in username or "SELECT" in username:
            # Vulnerable to SQL Injection: Raw SQL query
            query = text(f"SELECT * FROM user WHERE username = '{username}' OR email = '{email}' UNION SELECT 1, username, email, password, 0, 0, 0, 0 FROM user --")
            result = db.session.execute(query).fetchall()

            if result:
                retrieved_data = []
                for row in result:
                    retrieved_data.append({
                        'username': row[1], 
                        'email': row[2],    
                        'password': row[3], 
                    })

                flash(f"SQL Injection successful for {username}! See the results below:", 'success')
                return render_template('register.html', users=retrieved_data)

            flash('SQL Injection failed.', 'danger')
            return redirect(url_for('register'))

        # Normal registration logic if no SQL injection patterns detected
        try:
            # Check if username already exists in the database
            query = text(f"SELECT * FROM user WHERE username = :username")
            user_exists = db.session.execute(query, {'username': username}).fetchone()

            if user_exists:
                flash(f'Username {username} already exists.', 'danger')
                return redirect(url_for('register'))

            # Hash the password using SHA-1 before storing it
            sha1 = hashlib.sha1()
            sha1.update(password.encode('utf-8'))
            hashed_password = sha1.hexdigest()

            # Insert the new user into the database (use parameterized queries to avoid injection here)
            insert_query = text(f"INSERT INTO user (username, email, password) VALUES (:username, :email, :password)")
            db.session.execute(insert_query, {'username': username, 'email': email, 'password': hashed_password})
            db.session.commit()

            flash(f'Registration successful for {username}!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Database error: {e}", 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', users=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # First, check for a normal valid login using hashed password
            sha1 = hashlib.sha1()
            sha1.update(password.encode('utf-8'))  # Hash the password
            hashed_password = sha1.hexdigest()

            # Use a safe query for regular login check
            query = text(f"SELECT * FROM user WHERE username = :username AND password = :password")
            result = db.session.execute(query, {'username': username, 'password': hashed_password}).fetchone()

            if result:
                # Accessing the fields by index instead of string keys
                session['username'] = result[1]  # Assuming 'username' is the second field in the result tuple
                session.clear()
                return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f"Database error: {e}", 'danger')
            return redirect(url_for('login'))

        # If normal login fails, proceed to attempt SQL Injection (vulnerable part)
        try:
            # Vulnerable to SQL Injection: Raw SQL query
            query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}' UNION SELECT 1, username, email, password, 0, 0, 0, 0 FROM user -- ")
            result = db.session.execute(query).fetchall()

            if result:
                retrieved_data = []
                for row in result:
                    retrieved_data.append({
                        'username': row[1],  # Access by index
                        'email': row[2],     # Access by index
                        'password': row[3],  # Access by index
                    })

                flash('SQL Injection successful! See the results below:', 'success')
                return render_template('login.html', users=retrieved_data)
        except Exception as e:
            flash(f"Database error: {e}", 'danger')
            return redirect(url_for('login'))

        # If nothing is found, show invalid credentials
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html', users=[])

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
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

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
    search_query = request.args.get('search', '').strip()

    if search_query:
        # Vulnerable to SQL Injection: Raw SQL query
        query = text(f"SELECT * FROM customer WHERE full_name LIKE '%{search_query}%' OR email LIKE '%{search_query}%'")
        result = db.session.execute(query).fetchall()
        
        # Check if any results were found
        if result:
            # Assuming column indices: 1 for 'full_name', 2 for 'email', 5 for 'sector_id'
            users = [{'full_name': row[1], 'email': row[2], 'sector_id': row[3]} for row in result]
            print(f"Found users: {users}")  # Debug message
        else:
            users = []
            print("No users found for search query.")  # Debug message
    else:
        users = []
        print("No search query provided.")  # Debug message

    return render_template('admin.html', users=users)

@app.route('/admin-add-customer', methods=['POST'])
def admin_add_customer():
    full_name = request.form['full_name']
    email = request.form['email']
    sector_id = request.form['sector_id']

    try:
        # Vulnerable to SQL Injection: Directly using user inputs in SQL query
        query = text(f"SELECT * FROM customer WHERE email = '{email}' OR full_name = '{full_name}'")
        result = db.session.execute(query).fetchall()

        if result:
            retrieved_data = []
            for row in result:
                retrieved_data.append({
                    'full_name': row[1],
                    'email': row[2],
                    'sector_id': row[3],
                })

            # Display the SQL injection results in the template
            flash(f"SQL Injection successful! See the results below:", 'success')
            return render_template('admin_dashboard.html', customers=retrieved_data)

        # If no results, proceed with normal customer creation
        insert_query = text(f"INSERT INTO customer (full_name, email, sector_id) VALUES ('{full_name}', '{email}', {sector_id})")
        db.session.execute(insert_query)
        db.session.commit()

        flash(f"New customer {full_name} added successfully!", 'success')
        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        # Capture the error for debugging and display it to the user
        flash(f"Database error: {e}", 'danger')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)