# WebGuard
WebGuard is a full-stack web application that analyzes URLs and provides a rule-based risk assessment with an AI-generated explanation.

The application checks publicly accessible webpage information, identifies predefined security-related signals, calculates a risk score, and presents the result through a React-based interface.

## Features
* URL risk analysis
* Rule-based security scoring
* Webpage data extraction using Requests and BeautifulSoup
* Risk classification: Low, Medium, and High
* JWT-based user authentication
* Password hashing
* User-specific analysis history
* React and TypeScript frontend
* Flask REST API backend
* MySQL database
* AI-generated risk explanation using Ollama and TinyLlama
* Loading, error, and empty states

## How It Works
The analysis flow is:

1. User logs into WebGuard.
2. User enters a URL.
3. React sends the URL to the Flask REST API.
4. The backend validates and fetches the webpage.
5. Requests and BeautifulSoup extract relevant webpage information.
6. The rule-based engine checks predefined risk signals.
7. A risk score and risk level are calculated.
8. The analysis is stored in MySQL for the logged-in user.
9. The user can optionally request an AI-generated explanation.
10. Ollama with TinyLlama explains the detected signals in simple language.

## Architecture
```text
                    ┌──────────────────────┐
                    │      WebGuard UI     │
                    │   React + TypeScript │
                    └──────────┬───────────┘
                               │
                              Axios
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Flask REST API    │
                    │       Python         │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼─────────────────┐
              │                │                 │
              ▼                ▼                 ▼
       ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
       │ URL Analysis│  │Authentication│  │ AI Explanation│
       │             │  │    JWT       │  │    Endpoint   │
       └──────┬──────┘  └──────────────┘  └──────┬───────┘
              │                                   │
              ▼                                   ▼
       ┌─────────────┐                    ┌──────────────┐
       │  Requests + │                    │    Ollama    │
       │BeautifulSoup│                    │  TinyLlama   │
       └──────┬──────┘                    └──────────────┘
              │
              ▼
       ┌─────────────┐
       │ Rule-Based  │
       │ Risk Engine │
       └──────┬──────┘
              │
              ▼
       ┌─────────────┐
       │    MySQL    │
       │   Database  │
       └─────────────┘
```

## Risk Analysis
WebGuard currently uses a **rule-based scoring system** rather than allowing the LLM to determine the risk.

The analyzer checks signals such as:

* Missing HTTPS
* Suspicious keywords
* IP-address-based URLs
* Unusually long URLs
* Password fields
* Suspicious URL patterns

Each detected signal contributes points to the overall risk score.

The score is classified as:

* **0–29:** Low
* **30–59:** Medium
* **60–100:** High

The AI layer does **not** determine the risk score. It explains the signals already detected by the rule-based engine.

> WebGuard is a portfolio project and should not be treated as a replacement for professional security tools or a definitive determination that a website is malicious.

## Authentication
WebGuard uses JWT-based authentication.

### Registration
Users can create an account using:
* Name
* Email
* Password

Passwords are stored using password hashing rather than plain text.

### Login
After successful authentication, the backend generates a JWT access token.

Protected endpoints require:

```text
Authorization: Bearer <token>
```

The React application stores the token locally and attaches it to protected API requests using an Axios interceptor.

Analysis history is associated with the authenticated user, so users can access their own stored analyses.

## AI Explanation
WebGuard uses **Ollama** with the locally installed **TinyLlama** model.

The LLM receives the structured risk assessment rather than the complete webpage.

It is used to:

* Explain detected risk signals
* Summarize the reason for the risk level
* Provide a short safety recommendation

The rule-based engine remains responsible for the actual risk score.

## Technology Stack

### Frontend
* React.js
* TypeScript
* Axios
* CSS

### Backend
* Python
* Flask
* Flask-JWT-Extended
* Flask-SQLAlchemy
* Requests
* BeautifulSoup

### Database
* MySQL
* SQLAlchemy

### AI
* Ollama
* TinyLlama

### Development Tools
* Git
* GitHub
* Postman
* VS Code

## Project Structure
```text
WebGuard/
├── backend/
│   ├── models/
│   │   ├── analysis.py
│   │   └── user.py
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   ├── llm_service.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── App.css
│   │   ├── api.ts
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── .gitignore
└── README.md
```

Environment variables are configured using a local `.env` file, which is excluded from Git.

## API Endpoints
| Method | Endpoint        | Authentication | Purpose                         |
| ------ | --------------- | -------------- | ------------------------------- |
| GET    | `/api/health`   | No             | Check API status                |
| POST   | `/api/register` | No             | Register a new user             |
| POST   | `/api/login`    | No             | Authenticate a user             |
| POST   | `/api/analyze`  | Yes            | Analyze a URL                   |
| GET    | `/api/analyses` | Yes            | Get the user's analysis history |
| POST   | `/api/explain`  | Yes            | Generate an AI explanation      |

## Running Locally

### Prerequisites
Make sure the following are installed:
* Python 3.x
* Node.js and npm
* MySQL
* Ollama
* TinyLlama model

### 1. Clone the Repository
```bash
git clone https://github.com/Aleena107/WebGuard
cd WebGuard
```

### 2. Set Up the Backend
Open a terminal inside the `backend` directory:

```bash
python -m venv venv
```

Activate the virtual environment on Windows:

```bash
venv\Scripts\activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

### 3. Configure the Database
Create a MySQL database named:

```sql
CREATE DATABASE webguard;
```

Create a `.env` file inside the `backend` directory:

```text
DATABASE_URL=mysql+pymysql://root:YOUR_PASSWORD@localhost/webguard
JWT_SECRET_KEY=your-random-secret-value
```

Replace `YOUR_PASSWORD` with your local MySQL password.

### 4. Start Ollama
Make sure Ollama is running and TinyLlama is available:

```bash
ollama run tinyllama
```

### 5. Start the Backend
From the `backend` directory:

```bash
python app.py
```

The Flask API runs at:

```text
http://127.0.0.1:5000
```

### 6. Start the Frontend
Open another terminal and navigate to the frontend:

```bash
cd frontend
npm install
npm run dev
```

The React application will be available at the local Vite development URL shown in the terminal.

## Important Note
WebGuard uses publicly accessible webpage information and predefined rules to demonstrate URL analysis.

The risk score is based on the signals implemented in the project and does not guarantee that a website is safe or malicious.

The AI component is used only to explain the existing analysis and does not independently determine the security classification.

## Future Improvements
Potential improvements include:

* More advanced URL and domain analysis
* Additional phishing and suspicious-pattern detection rules
* Automated backend testing with pytest
* Postman API collection
* Improved error handling for inaccessible websites
* More detailed analysis history
* Improved AI-generated explanations
* Deployment using a cloud platform
* More comprehensive security validation
