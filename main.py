import requests
import ssl
import socket
import time
import re
from urllib.parse import urlparse

# Disable SSL/TLS verification warnings
ssl._create_default_https_context = ssl._create_unverified_context

def get_website_region(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        if response.ok:
            data = response.json()
            return data.get("regionName")
        else:
            print(f"❌ Could not retrieve region for IP address {ip_address}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not connect to GeoIP API: {e}")

def check_website_security(url):
    # Parse the URL and extract the hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # Retrieve the IP address of the website
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"\n🔍 IP address of {hostname}: {ip_address}")
    except socket.gaierror as e:
        print(f"❌ Could not resolve hostname {hostname}: {e}")

    # Retrieve the region of the IP address
    region = get_website_region(ip_address)
    if region:
        print(f"🌎 {hostname} is hosted in {region}.")
    else:
        print(f"❌ Could not retrieve region for IP address {ip_address}.")

    # Make a GET request to the website and check if the SSL/TLS certificate is valid
    try:
        print("\nLoading...")
        time.sleep(2)  # Add a 2-second delay to simulate loading
        response = requests.get(url)
        if response.ok:
            connection = response.raw._connection
            if connection and connection.sock:
                cert = connection.sock.getpeercert()
                if not cert:
                    print(f"\n❌ {hostname} does not have a valid SSL/TLS certificate.")
                else:
                    print(f"\n✅ {hostname} has a valid SSL/TLS certificate.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not connect to {hostname}: {e}")

    # Retrieve some details about the website
    try:
        response = requests.get(url)
        if response.ok:
            content_type = response.headers.get("Content-Type")
            server = response.headers.get("Server")
            print(f"\n🌐 {hostname} is running {server} and serving content of type {content_type}.")

            # Check if the website is a phishing website
            if "text/html" in content_type:
                text = response.text.lower()
                if "Login" in text or "Signin" in text or "log in" in text or "sign in" in text:
                    if "password" in text or "email" in text or "username" in text:
                        print(f"\n⚠️  {hostname} might be a phishing website.")
                    else:
                        print(f"\n✅ {hostname} is probably not a phishing website.")
                else:
                    print(f"\n✅ {hostname} is probably not a phishing website.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not connect to {hostname}: {e}")

    # Find all subdomains of the website and check if they are active
    print(f"\n🔎 Subdomains of {hostname}:")
    subdomains = find_subdomains(hostname)
    for subdomain in subdomains:
        subdomain_url = f"https://{subdomain}.{hostname}"
        try:
            response = requests.get(subdomain_url)
            if response.ok:
                print(f"✅ {subdomain_url} is active.")
            else:
                print(f"❌ {subdomain_url} is inactive.")
        except requests.exceptions.RequestException:
            print(f"❌ {subdomain_url} is inactive.")

    # Find all email addresses and usernames mentioned on the website
    print(f"\n📧 Email addresses and usernames mentioned on {hostname}:")
    response = requests.get(url)
    if response.ok:
        emails_users = find_emails_usernames(response.text)
        if not emails_users[0] and not emails_users[1]:
            print("No email addresses or usernames found.")
        else:
            if emails_users[0]:
                print(f"📬 Email addresses: {emails_users[0]}")
            if emails_users[1]:
                print(f"🧑 Usernames: {emails_users[1]}")
    else:
        print("Could not retrieve website content.")

def check_phishing(url):
    try:
     
        

        # Check for redirects
        response = requests.get(url, allow_redirects=False)
        if response.status_code >= 300 and response.status_code < 400:
            print(f"\n🚩  {url} (redirect detected)")

        # Check for JavaScript redirects
        if re.search(r"window.location\s*=", response.text):
            print(f"\n🚩  {url} (JavaScript redirect detected)")

        # Check for phishing indicators using regular expressions
        if re.search(r"(paypal.com|paypal\.com|paypal-com\.com|paypal-login\.com)", url, re.IGNORECASE):
            print(f"\n🚩  {url} (suspicious URL)")

        if "text/html" in response.headers.get("Content-Type"):
            text = response.text.lower()

            # Check for fake login forms
            if re.search(r"login|signin|log in|sign in", text) and (re.search(r"password", text) or re.search(r"email|username", text)):
                print(f"\n🚩  {url} (fake login form detected)")

            # Check for misspelled URLs
            if re.search(r"paypa1|paypai|paypall|paypal1", text):
                print(f"\n🚩  {url} (misspelled URL detected)")

    except requests.exceptions.RequestException as e:
        print(f"❌ Could not connect to {url}: {e}")

def find_subdomains(domain_name):
    """
    Finds all subdomains of a given domain name.
    """
    subdomains = set()
    for i in range(1, 10):  # Search up to 10 levels deep
        subdomain = f"{'.'.join(domain_name.split('.')[:-i])}"
        if subdomain != domain_name:
            subdomains.add(subdomain)
        else:
            break
    return subdomains

def find_emails_usernames(text):
    """
    Finds all email addresses and usernames in a given text.
    """
    import re

    # Define regular expressions for email addresses and usernames
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    username_regex = r'\B@\w+(?!\.)'

    # Find all email addresses and usernames in the text
    emails = re.findall(email_regex, text)
    usernames = re.findall(username_regex, text)

    # Remove duplicates from the lists and return them
    return list(set(emails)), list(set(usernames))




# Prompt the user to enter a URL
url = input("👉 Enter a website URL: ")

# Check the security of the website and retrieve some details
check_website_security(url)
check_phishing(url)












