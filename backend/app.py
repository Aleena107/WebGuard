from flask import Flask, jsonify, request
from flask_cors import CORS
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from flask_cors import CORS
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from config import Config
from database import db

from models.analysis import Analysis

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
CORS(app)

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "success",
        "message": "WebGuard backend is running"
    })


@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    url = data["url"].strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL cannot be empty"
        }), 400

    parsed_url = urlparse(url)

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        page_title = (
            soup.title.get_text(strip=True)
            if soup.title
            else "No title found"
        )

        forms_count = len(soup.find_all("form"))
        links_count = len(soup.find_all("a"))
        images_count = len(soup.find_all("img"))
        scripts_count = len(soup.find_all("script"))

        password_fields = soup.find_all(
            "input",
            {"type": "password"}
        )

        password_field_count = len(password_fields)

        webpage_data = {
            "title": page_title,
            "forms": forms_count,
            "links": links_count,
            "images": images_count,
            "scripts": scripts_count,
            "password_fields": password_field_count
        }

    except requests.RequestException:
        webpage_data = {
            "title": "Unable to fetch webpage",
            "forms": 0,
            "links": 0,
            "images": 0,
            "scripts": 0
        }

    if not parsed_url.scheme or not parsed_url.netloc:
        return jsonify({
            "status": "error",
            "message": "Please enter a valid URL"
        }), 400

    score = 0
    signals = []

    # Check HTTPS
    if parsed_url.scheme != "https":
        score += 15
        signals.append({
            "name": "HTTPS not enabled",
            "points": 15,
            "severity": "medium"
        })

    # Check URL length
    if len(url) > 75:
        score += 10
        signals.append({
            "name": "Unusually long URL",
            "points": 10,
            "severity": "low"
        })

    # Check suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "account",
        "password",
        "security",
        "update",
        "confirm"
    ]

    found_keywords = [
        keyword for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if found_keywords:
        score += 15
        signals.append({
            "name": "Suspicious keywords detected",
            "points": 15,
            "severity": "medium",
            "keywords": found_keywords
        })

        # Check for suspicious URL characters
    suspicious_characters = ["@", "//"]

    found_patterns = [
        pattern
        for pattern in suspicious_characters
        if pattern in parsed_url.path
    ]

    if found_patterns:
        score += 10

        signals.append({
            "name": "Suspicious URL pattern detected",
            "points": 10,
            "severity": "medium"
        })

    # Check whether an IP address is being used
    hostname = parsed_url.hostname or ""

    if hostname.replace(".", "").isdigit():
        score += 25
        signals.append({
            "name": "IP address used instead of domain",
            "points": 25,
            "severity": "high"
        })

        # Check for password fields
    if password_field_count > 0:
        score += 20

        signals.append({
            "name": "Password field detected",
            "points": 20,
            "severity": "medium"
        })

    # Determine risk level
    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    analysis = Analysis(
        url=url,
        risk_score=score,
        risk_level=risk_level,
        page_title=webpage_data["title"],
        forms=webpage_data["forms"],
        links=webpage_data["links"],
        images=webpage_data["images"],
        scripts=webpage_data["scripts"],
        password_fields=webpage_data["password_fields"]
    )

    db.session.add(analysis)
    db.session.commit()

    return jsonify({
        "status": "success",
        "data": {
            "id": analysis.id,
            "url": url,
            "risk_score": score,
            "risk_level": risk_level,
            "signals": signals,
            "webpage": webpage_data
        }
    })

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)