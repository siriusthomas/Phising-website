from flask import Flask, render_template, request
import pickle
import numpy as np
import requests
from urllib.parse import urlparse
import re
import logging
from datetime import datetime
import socket
import whois

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained XGBoost model
model = pickle.load(open("XGBoostClassifier.pickle (9).dat", "rb"))

# Load phishing sites list
with open("phishing_sites.pkl", "rb") as file:
    phishing_sites = pickle.load(file)

# Load legitimate sites list
with open("legitimate_sites.pkl", "rb") as file:
    legitimate_sites = pickle.load(file)

# API Keys final
GOOGLE_API_KEY = "AIzaSyBV5r3dy4QXcW3xc1MvvGpkEM8nj6gOs8g"
WHOIS_API_KEY = "at_H8FLriFFhGAY2BVn4UOedITLrgZjn"
WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

def check_website_exists(domain):
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"Domain {domain} resolved to IP {ip}")  # Log the resolved IP
        if ip in ["0.0.0.0", "127.0.0.1"]:  # Ignore local/unresolved domains
            return False
        return True
    except socket.gaierror:
        logging.error(f"DNS resolution failed for {domain}")
        return False

def is_domain_real(domain):
    dns_check = check_website_exists(domain)
    logging.info(f"Domain {domain} - DNS check: {dns_check}")
    return dns_check


    
    
    
    return dns_check and whois_check

# Function to check Google Safe Browsing API
def check_google_safe_browsing(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        data = {
            "client": {"clientId": "yourapp", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(api_url, json=data)
        result = response.json()
        return "matches" in result
    except requests.exceptions.RequestException as e:
        logging.error(f"Google Safe Browsing API error: {e}")
        return False

# Function to check PhishTank database
def check_phishtank(url):
    try:
        response = requests.get(f"https://www.phishtank.com/checkurl/{url}")
        return "phishing" in response.text.lower()
    except requests.exceptions.RequestException as e:
        logging.error(f"PhishTank API error: {e}")
        return False

# Function to get domain age
def get_domain_age(domain):
    try:
        response = requests.get(f"{WHOIS_API_URL}?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=json")
        data = response.json()
        creation_date_str = data.get("WhoisRecord", {}).get("createdDate")
        if not creation_date_str:
            return "Unknown"
        creation_date = datetime.strptime(creation_date_str.split("T")[0], "%Y-%m-%d")
        domain_age = (datetime.now() - creation_date).days // 365
        return domain_age
    except Exception as e:
        logging.error(f"Error fetching domain age: {e}")
        return "Unknown"

# Function to extract features from a URL
def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        raise ValueError("Invalid URL: Missing domain")
    domain_age = get_domain_age(domain)
    domain_age = -1 if domain_age == "Unknown" else domain_age
    features = [
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0,  # Have_IP
        1 if "@" in url else 0,  # Have_At
        len(url),  # URL_Length
        url.count("/"),  # URL_Depth
        url.count("//"),  # Redirection
        1 if parsed.scheme == "https" else 0,  # https_Domain
        1 if "tinyurl" in url else 0,  # TinyURL
        1 if "-" in domain else 0,  # Prefix/Suffix
        0,  # DNS_Record
        0,  # Web_Traffic
        domain_age,  # Domain_Age
        len(domain.split(".")[-1]),  # Domain_End
        1 if "iframe" in url else 0,  # iFrame
        1 if "onmouseover" in url else 0,  # Mouse_Over
        1 if "rightclick" in url else 0,  # Right_Click
        1 if "refresh" in url else 0,  # Web_Forwards
    ]
    return np.array(features).reshape(1, -1)

@app.route('/')
def home():
    return render_template('index1.html')

@app.route('/predict', methods=['POST'])
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url', '').strip()
    if not url:
        return render_template('index1.html', error="Please enter a URL")
    
    logging.info(f"Received URL: {url}")

    domain = urlparse(url).netloc.lower()
    
    # Normalize domain by stripping 'www.'
    domain = domain.lstrip('www.')

    logging.info(f"Extracted Domain: {domain}")


    if domain in legitimate_sites:
        return render_template('index1.html', url=url, prediction="Legitimate", domain_age="N/A")

    if not is_domain_real(domain):
        return render_template('index1.html', url=url, prediction="Domain does not exist", confidence="N/A")

    if domain in phishing_sites:
        return render_template('index1.html', url=url, prediction="Phishing", domain_age="N/A")

    domain_age = get_domain_age(domain)

    if check_google_safe_browsing(url):
        return render_template('index1.html', url=url, prediction="Phishing (Google Safe Browsing)", domain_age=domain_age)

    if check_phishtank(url):
        return render_template('index1.html', url=url, prediction="Phishing (PhishTank)", domain_age=domain_age)

    try:
        features = extract_features(url)
    except Exception as e:
        logging.error(f"Feature extraction failed: {e}")
        return render_template('index1.html', error=f"Feature extraction error: {str(e)}")

    probabilities = model.predict_proba(features)[0]
    phishing_prob = probabilities[1]
    threshold = 0.94
    result = "Phishing" if phishing_prob > threshold else "Legitimate"

    return render_template('index1.html', url=url, prediction=result, confidence=round(phishing_prob * 100, 2), domain_age=domain_age)


if __name__ == '__main__':
    app.run(debug=True)
