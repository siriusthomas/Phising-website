from flask import Flask, render_template, request
import pickle
import numpy as np
import requests
from urllib.parse import urlparse
import re
import logging
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained XGBoost model
model = pickle.load(open("XGBoostClassifier.pickle (9).dat", "rb"))

# Load phishing sites list
with open("phishing_sites.pkl", "rb") as file:
    phishing_sites = pickle.load(file)

# API Keys final
GOOGLE_API_KEY = "AIzaSyBV5r3dy4QXcW3xc1MvvGpkEM8nj6gOs8g"
WHOIS_API_KEY = "at_H8FLriFFhGAY2BVn4UOedITLrgZjn"
WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

# Function to check Google Safe Browsing API
def check_google_safe_browsing(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        data = {
            "client": {"clientId": "yourapp", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(api_url, json=data)
        result = response.json()
        
        if "matches" in result:
            return True  # URL is flagged as unsafe
    except requests.exceptions.RequestException as e:
        logging.error(f"Google Safe Browsing API error: {e}")
    
    return False  # URL is not flagged

# Function to check PhishTank database
def check_phishtank(url):
    try:
        response = requests.get(f"https://www.phishtank.com/checkurl/{url}")
        if "phishing" in response.text.lower():
            return True  # URL is reported as phishing
    except requests.exceptions.RequestException as e:
        logging.error(f"PhishTank API error: {e}")
    return False  # URL is not found in PhishTank


def get_domain_age(domain):
    api_url = f"https://whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=json"

    try:
        response = requests.get(api_url)
        data = response.json()

        creation_date_str = data.get("WhoisRecord", {}).get("createdDate")

        if not creation_date_str:
            return "Unknown"  # Return 'Unknown' if no date is found

        creation_date = datetime.strptime(creation_date_str.split("T")[0], "%Y-%m-%d")
        current_date = datetime.now()

        domain_age = (current_date - creation_date).days // 365  # Convert to years
        return domain_age

    except Exception as e:
        logging.error(f"Error fetching domain age: {e}")
        return "Error"


def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  

    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain:
        raise ValueError("Invalid URL: Missing domain")

    domain_age = get_domain_age(domain)
    if domain_age == "Unknown" or domain_age == "Error":
        domain_age = -1  

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

    if len(features) != 16:
        raise ValueError(f"Feature extraction error: Expected 16, got {len(features)}")

    return np.array(features).reshape(1, -1)

@app.route('/')
def home():
    return render_template('index1.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url', '').strip()

    if not url:
        return render_template('index.html', error="Please enter a URL")

    logging.info(f"Received URL: {url}")

    domain = urlparse(url).netloc.lower()

    # Check phishing sites list first
    if domain in phishing_sites:
        logging.warning(f"URL {url} found in phishing sites list")
        return render_template('index.html', url=url, prediction="Phishing ", domain_age="N/A")

    # Get domain age
    domain_age = get_domain_age(domain)

    if check_google_safe_browsing(url):
        return render_template('index.html', url=url, prediction="Phishing (Reported by Google Safe Browsing)", domain_age=domain_age)

    if check_phishtank(url):
        return render_template('index.html', url=url, prediction="Phishing (Reported by PhishTank)", domain_age=domain_age)

    try:
        features = extract_features(url)
    except Exception as e:
        logging.error(f"Feature extraction failed for {url}: {e}")
        return render_template('index.html', error=f"Feature extraction error: {str(e)}")

    probabilities = model.predict_proba(features)[0]
    phishing_prob = probabilities[1]
    threshold = 0.94 
    result = "Phishing" if phishing_prob > threshold else "Legitimate"

    logging.info(f"Prediction for {url} | Probability: {phishing_prob:.3f} | Result: {result}")

    return render_template('index1.html', url=url, prediction=result, confidence=round(phishing_prob * 100, 2), domain_age=domain_age)

if __name__ == '__main__':
    app.run(debug=True)
