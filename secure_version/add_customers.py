import requests
from bs4 import BeautifulSoup

# The URL of the add customer form
add_customer_url = "http://127.0.0.1:5000/admin-add-customer" 

# List of full names for customers
full_names = [
    'John Smith', 'Emma Johnson', 'Oliver Brown', 'Sophia Taylor', 'Liam Anderson', 
    'Ava Martinez', 'Noah Garcia', 'Isabella Lopez', 'Elijah Lee', 'Mia Perez', 
    'James Clark', 'Amelia Hernandez', 'William Davis', 'Charlotte Lewis', 
    'Benjamin Walker', 'Evelyn Hall', 'Lucas Young', 'Harper King', 'Henry Wright', 
    'Ella Scott', 'Alexander Adams', 'Abigail Baker', 'Jackson Green', 
    'Scarlett Nelson', 'Sebastian Hill', 'Grace Mitchell', 'Mateo Campbell', 
    'Chloe Carter', 'Jack Roberts', 'Victoria Murphy', 'Daniel Morris', 
    'Luna Cooper', 'Owen Ward', 'Hannah Reed', 'Caleb Cox', 'Zoe Cook', 
    'Samuel Morgan', 'Addison Bell', 'Levi Parker', 'Violet Bailey', 
    'Ethan Evans', 'Lily Rivera', 'Michael Butler', 'Emily Gonzalez', 
    'Jacob Sanders', 'Aria Rogers', 'Logan Price', 'Avery Foster', 
    'David Gray', 'Nora Brooks', 'Isaac Russell', 'Layla Griffin'
]

# Function to add a customer
def add_customer(full_name, email, sector_id):
    # Data to be sent in the add customer form
    data = {
        "full_name": full_name,
        "email": email,
        "sector_id": sector_id
    }
    
    # Send POST request to the add customer form
    response = requests.post(add_customer_url, data=data)
    soup = BeautifulSoup(response.content, "html.parser")

    # Output the result
    print(f"Attempted to add customer: {full_name}")
    print("Page title:", soup.title.string if soup.title else "No title")
    print("-" * 40)

# Loop through the first 50 names and add them to sector 1
for i in range(50):
    add_customer(full_names[i], f"customer{i+1}@example.com", 1)

# Loop through the next 50 names and add them to sector 2
for i in range(50, 100):
    add_customer(full_names[i % 50], f"customer{i+1}@example.com", 2)
