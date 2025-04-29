# 🛡️ Phishing Website Detector

A Flask-based web application that detects whether a given URL is **phishing (scam)** or **legitimate** using a trained machine learning model and public safety APIs.

---

## Features

- 🔍 Detects phishing websites using an **XGBoost classifier**
- 🌐 Displays **domain age** using WHOIS API
- 🛡️ Checks against **Google Safe Browsing API**
- 🎣 Verifies with **PhishTank** database
- 🧠 Extracts 16+ URL-based features for prediction
- 📊 Outputs phishing probability with confidence score
- 🖥️ Simple and clean HTML interface

---

##  How It Works

1. User enters a website URL.
2. URL is first checked against:
   - A blacklist of known phishing domains
   - Google Safe Browsing
   - PhishTank
3. Domain age is fetched using the WHOIS API.
4. 16+ features are extracted from the URL.
5. Features are passed to a trained **XGBoost model**.
6. Result is displayed with prediction and domain information.

---

## 📁 Project Structure

