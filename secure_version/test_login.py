import requests
from bs4 import BeautifulSoup

# The URL of the login form
login_url = "http://127.0.0.1:5000/login" 

# Sample payloads to test for SQL Injection and other vulnerabilities
payloads = [
    "' OR 1=1 --",    # SQL Injection attempt
    "' OR 'a'='a",    # SQL Injection with simple string comparison
    "' OR '1'='1",    # Another SQL Injection variation
    "<script>alert('XSS');</script>",  # XSS Injection attempt
    "admin'--",       # SQL Injection (authentication bypass)
]

# Function to perform login
def test_login(username_payload, password_payload):
    # Data to be sent in the login form
    data = {
        "username": username_payload,
        "password": password_payload
    }

    # Send a POST request to the login page
    response = requests.post(login_url, data=data)
    
    # Parse the HTML content
    soup = BeautifulSoup(response.content, "html.parser")
    
    # Get flash message if exists
    flash_message = soup.find(class_="alert-danger")  # Look for error messages in your response
    
    # Print out the response status code
    print(f"Testing with payload: {username_payload} / {password_payload}")
    print(f"Status Code: {response.status_code}")

    # Analyze the flash message or page content
    if flash_message and "Invalid input detected" in flash_message.text:
        print("Attack detected and blocked: Invalid input detected.")
    elif flash_message and "Invalid username or password" in flash_message.text:
        print("Login failed as expected.")
    else:
        print("Potential vulnerability found or bypass succeeded!")
    
    # Optional: Print the page title
    page_title = soup.title.string if soup.title else "No title"
    print(f"Page title: {page_title}")
    print("-" * 40)

# Loop through each payload and test it
for payload in payloads:
    # Test the payload in both username and password fields
    test_login(payload, "password123")  # Test with payload in the username field
    test_login("admin", payload)        # Test with payload in the password field