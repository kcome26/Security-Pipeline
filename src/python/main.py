import hashlib

# Hardcoded credentials - security issue for testing
password = "hardcoded_password"

def main():
    print("Hello from Python")
    
    # Weak crypto - security issue for testing
    hashed = hashlib.md5(password.encode()).hexdigest()
    print(f"Weak hash: {hashed}")
    
    # SQL injection vulnerability example
    user_id = input("Enter user ID: ") if __name__ == "__main__" else "1"
    query = f"SELECT * FROM users WHERE id = {user_id}"
    print(query)

if __name__ == "__main__":
    main()
