import os
import sqlite3

# Read the admin credentials from environment variables
admin_username = os.environ.get('ADMIN_USERNAME')
admin_password = os.environ.get('ADMIN_PASSWORD')

# Connect to the database and create tables
conn = sqlite3.connect('insecure_websites.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS websites (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE)''')
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, is_admin INTEGER DEFAULT 0)''')

# Create admin account if it doesn't exist
c.execute("INSERT INTO users (username, password, is_admin) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ?)", (admin_username, admin_password, 1, admin_username))
conn.commit()

# Function to add a website to the database
def add_website(url):
    c.execute("INSERT INTO websites (url) VALUES (?)", (url,))
    conn.commit()
    print("👍 Website added successfully")

# Function to retrieve all websites from the database
def get_websites():
    c.execute("\nSELECT * FROM websites")
    websites = c.fetchall()
    return websites

# Function to create a new user account
def create_user(username, password):
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    print("👤 User account created successfully")

# Function to check if a user exists in the database
def check_login(username, password):
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    row = c.fetchone()
    return bool(row)

# Function to check if a user is an admin
def check_admin(username):
    c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    return row and row[0] == 1

# Function to check if a username already exists in the database
def check_username(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return bool(c.fetchone())

# Function to add a user to the database
def add_user(username, password):
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    
def delete_user(username):
    if check_admin(username):
        print("❌ Admins cannot be deleted")
    else:
        c.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        print("👤 User account deleted successfully")

def change_credentials(username):
    print("\n1. Change username")
    print("2. Change password")
    print("3. Change both")
    choice = input("Please enter your choice: ")
    if choice == "1":
        new_username = input("\n👤 Please enter your new username: ")
        if check_username(new_username):
            print("Username already exists. Please choose a different one.")
            return
        c.execute("UPDATE users SET username=? WHERE username=?", (new_username, username))
        conn.commit()
        print("👤 Username changed successfully")
    elif choice == "2":
        new_password = input("\n🔒 Please enter your new password: ")
        c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        print("🔒 Password changed successfully")
    elif choice == "3":
        new_username = input("\n👤 Please enter your new username: ")
        if check_username(new_username):
            print("Username already exists. Please choose a different one.")
            return
        new_password = input("\n🔒 Please enter your new password: ")
        c.execute("UPDATE users SET username=?, password=? WHERE username=?", (new_username, new_password, username))
        conn.commit()
        print("👤🔒 Username and password changed successfully")
    else:
        print("Invalid choice. Please try again.")


while True:
    print("\nRedflag / reported websites 🌐\n")
    print("1. Log in 🔑")
    print("2. Create new account 🆕")
    choice = input("Please enter your choice: ")
        
    if choice == "1":
        username = input("\n👤 Please enter your username: ")
        password = input("🔒 Please enter your password: ")
            
        if check_login(username, password):
            print("\nLogged in successfully! 🎉")
                
            while True:
                print("\n1. View websites 🌐")
                print("2. Add user 👤")
                print("3. Delete user ❌👤")
                print("4. Add website 🆕")
                print("5. Clear list 🗑️")
                print("6. Get all users 👥")
                print("7. Change username or password")
                print("8. Log out 🚪")
                user_choice = input("Please enter your choice: ")
                    
                if user_choice == "1":
                    websites = get_websites()
                    for website in websites:
                        print(website[0], website[1])
                            
                elif user_choice == "2":
                    if check_admin(username):
                        new_username = input("\n👤 Please enter the new user's username: ")
                        new_password = input("🔒 Please enter the new user's password: ")
                        create_user(new_username, new_password)
                        print("\n User account created successfully! 🎉")
                    else:
                        print("⛔ You don't have permission to add a user")
                
                elif user_choice == "3":
                    if check_admin(username):
                        del_username = input("\n❌👤 Please enter the username of the account to delete: ")
                        delete_user(del_username)
                    else:
                        print("⛔ You don't have permission to delete a user")
                
                elif user_choice == "4":
                    new_website = input("🏴󠁡󠁵󠁮󠁳󠁿 Please enter the URL of the new website: ")
                    add_website(new_website)
                            
                elif user_choice == "5":
                    if check_admin(username):
                        confirm = input("❓ Are you sure you want to clear the list? This cannot be undone. (y/n) ")
                        if confirm == "y":
                            c.execute("DELETE FROM websites")
                            conn.commit()
                            print("List cleared successfully! 🗑️🎉")
                        else:
                            print("List not cleared")
                    else:
                        print("⛔ You don't have permission to clear the list")

                




                elif user_choice == "8":
                    change_credentials(username)
                    

                elif user_choice == "7":
                    print("\n Logged out successfully! 👋")
                    break

                else:
                    print("Invalid choice. Please try again. ❌")
            
        else:
            print("Invalid username or password. Please try again. ❌")
                
    elif choice == "2":
        new_username = input("\n👤 Please enter your desired username: ")
        new_password = input("🔒 Please enter your desired password: ")
                
        if check_username(new_username):
            print("⛔ Username already exists, please choose a different username. ⛔")
                    
        else:
            add_user(new_username, new_password)
        print("\nAccount created successfully! 🎉")

    # Prompt user to log in or exit the program
    while True:
        print("\n1. Log in 🔑")
        print("2. Exit 🚪")
        choice = input("Please enter your choice: ")

        if choice == "1":
            username = input("\n👤 Please enter your username: ")
            password = input("🔒 Please enter your password: ")

            if check_login(username, password):
                print("\nLogged in successfully! 🎉")

                while True:
                    print("\n1. View websites 🌐")
                    print("2. Add user 👤")
                    print("3. Delete user ❌👤")
                    print("4. Add website 🆕")
                    print("5. Clear list 🗑️")
                    print("6. Get all users 👥 (Does not currently work)")
                    print("7. Change username or password")
                    print("8. Log out 🚪")
                    user_choice = input("Please enter your choice: ")
                    
                    if user_choice == "1":
                        websites = get_websites()
                        for website in websites:
                            print(website[0], website[1])
                    
                    elif user_choice == "2":
                        if check_admin(username):
                            new_username = input("\n👤 Please enter the new user's username: ")
                            new_password = input("🔒 Please enter the new user's password: ")
                            create_user(new_username, new_password)
                            print("\n User account created successfully! 🎉")
                        else:
                            print("⛔ You don't have permission to add a user")
                    
                    elif user_choice == "3":
                        if check_admin(username):
                            del_username = input("\n❌👤 Please enter the username of the account to delete: ")
                            delete_user(del_username)
                        else:
                            print("⛔ You don't have permission to delete a user")
                    
                    elif user_choice == "4":
                        new_website = input("🏴󠁡󠁵󠁮󠁳󠁿 Please enter the URL of the new website: ")
                        add_website(new_website)
                    elif user_choice == "5":
                        if check_admin(username):
                            confirm = input("❓ Are you sure you want to clear the list? This cannot be undone. (y/n) ")
                            if confirm == "y":
                                c.execute("DELETE FROM websites")
                                conn.commit()
                                print("List cleared successfully! 🗑️🎉")
                            else:
                                print("List not cleared")
                        else:
                            print("⛔ You don't have permission to clear the list")
                    elif user_choice == "6":
                        print("This option does not currently work.")
                    elif user_choice == "7":
                        change_credentials(username)
                        print("\n Logged out successfully! 👋")
                        break
                    elif user_choice == "8":
                        print("\n Logged out successfully! 👋")
                        break
                    else:
                        print("Invalid choice. Please try again. ❌")
                        if choice == "2":
                            print("\n Goodbye! 👋")
                            break
                        else:
                            print("Invalid choice. Please try again. ❌")





