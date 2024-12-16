import requests
from bs4 import BeautifulSoup

# The URL of the registration form
register_url = "http://127.0.0.1:5000/register" 

# Sample payloads to test for SQL Injection and XSS in the registration form
payloads = [
    "' OR 1=1 --",    # SQL Injection attempt
    "' OR 'a'='a",    # SQL Injection with simple string comparison
    "' OR '1'='1",    # SQL Injection variation
    "<script>alert('XSS');</script>",  # XSS Injection attempt
    "admin'--",       # SQL Injection (authentication bypass)
]

# Function to perform register test
def test_register(username_payload, email_payload, password_payload, confirm_password_payload):
    # Data to be sent in the registration form
    data = {
        "username": username_payload,
        "email": email_payload,
        "sector_id": 1,
        "password": password_payload,
        "confirm-password": confirm_password_payload
    }

    # Send POST request to the registration page
    response = requests.post(register_url, data=data)

    # Print out the response status code and details
    print(f"Testing with payload: {username_payload} / {email_payload} / {password_payload} / {confirm_password_payload}")
    print(f"Status Code: {response.status_code}")
    
    # Analyze the response content for success/failure
    if "Registration successful!" in response.text:
        print("Registration successful - No vulnerability found!")
    elif "Invalid input detected" in response.text:
        print("Potential SQL Injection or XSS detected and blocked.")
    elif "Username already exists" in response.text:
        print("Username already taken, as expected.")
    elif "Passwords do not match" in response.text:
        print("Password mismatch error shown, as expected.")
    else:
        print("Unexpected response - Further analysis needed.")

    # Optional: Print page title and separator
    soup = BeautifulSoup(response.content, "html.parser")
    print("Page title:", soup.title.string if soup.title else "No title")
    print("-" * 40)

# Loop through each payload and test it
for payload in payloads:
    # Test with the payload in username, email, password, and confirm password fields
    test_register(payload, "test@example.com", "password123", "password123")  # Payload in the username
    test_register("testuser", payload, "password123", "password123")           # Payload in the email
    test_register("testuser", "test@example.com", payload, payload)            # Payload in both password fields
    