import { useEffect, useState } from "react";
import axios from "axios";
import api from "./api";
import "./App.css";

interface Signal {
  name: string;
  points: number;
  severity: string;
  keywords?: string[];
}

interface AnalysisResult {
  url: string;
  risk_score: number;
  risk_level: string;
  signals: Signal[];
  webpage: {
    title: string;
    forms: number;
    links: number;
    images: number;
    scripts: number;
    password_fields: number;
  };
}

interface AnalysisHistory {
  id: number;
  url: string;
  risk_score: number;
  risk_level: string;
  page_title: string;
  forms: number;
  links: number;
  images: number;
  scripts: number;
  password_fields: number;
  created_at: string;
}

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [history, setHistory] = useState<AnalysisHistory[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const [isAuthenticated, setIsAuthenticated] = useState(
    !!localStorage.getItem("access_token")
  );

  const [showRegister, setShowRegister] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);

  const [aiExplanation, setAiExplanation] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");

  // -----------------------------
  // Fetch Analysis History
  // -----------------------------
  const fetchHistory = async () => {
    try {
      setHistoryLoading(true);

      const token = localStorage.getItem("access_token");

      if (!token) {
        setHistory([]);
        return;
      }

      const response = await api.get("/analyses");

      setHistory(response.data.data);
    } catch (error: any) {
      console.error("Failed to fetch analysis history:", error);

      if (error.response?.status === 401) {
        localStorage.removeItem("access_token");
        setIsAuthenticated(false);
        setHistory([]);
      }
    } finally {
      setHistoryLoading(false);
    }
  };

  // -----------------------------
  // Login
  // -----------------------------
  const handleLogin = async () => {
    if (!email.trim() || !password.trim()) {
      setAuthError("Email and password are required.");
      return;
    }

    try {
      setAuthLoading(true);
      setAuthError("");

      const response = await axios.post(
        "http://127.0.0.1:5000/api/login",
        {
          email,
          password,
        }
      );

      const token = response.data.data.access_token;

      localStorage.setItem("access_token", token);

      setIsAuthenticated(true);
      setPassword("");

      // Load user's history after successful login
      await fetchHistory();
    } catch (error: any) {
      setAuthError(
        error.response?.data?.message || "Login failed."
      );
    } finally {
      setAuthLoading(false);
    }
  };

  // -----------------------------
  // Register
  // -----------------------------
  const handleRegister = async () => {
    if (!name.trim() || !email.trim() || !password.trim()) {
      setAuthError("Name, email and password are required.");
      return;
    }

    try {
      setAuthLoading(true);
      setAuthError("");

      await axios.post(
        "http://127.0.0.1:5000/api/register",
        {
          name,
          email,
          password,
        }
      );

      // Switch back to login
      setShowRegister(false);
      setName("");

      // Automatically login using the same credentials
      await handleLogin();
    } catch (error: any) {
      setAuthError(
        error.response?.data?.message || "Registration failed."
      );
    } finally {
      setAuthLoading(false);
    }
  };

  // -----------------------------
  // Logout
  // -----------------------------
  const handleLogout = () => {
    localStorage.removeItem("access_token");

    setIsAuthenticated(false);
    setHistory([]);
    setResult(null);
    setUrl("");
    setError("");
  };

  const explainWithAI = async () => {
  if (!result) {
    return;
  }

  try {
    setAiLoading(true);
    setAiError("");
    setAiExplanation("");

    const response = await api.post("/explain", {
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      signals: result.signals,
      webpage: result.webpage,
    });

    setAiExplanation(
      response.data.data.explanation
    );
  } catch (error: any) {
    console.error(
      "Failed to generate AI explanation:",
      error
    );

    if (error.response?.status === 401) {
      localStorage.removeItem("access_token");
      setIsAuthenticated(false);
      setAiError("Your session has expired. Please login again.");
    } else {
      setAiError(
        error.response?.data?.message ||
          "Unable to generate AI explanation."
      );
    }
  } finally {
    setAiLoading(false);
  }
};

  // -----------------------------
  // Analyze URL
  // -----------------------------
  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setAiExplanation("");
    setAiError("");

    try {
      // JWT is automatically added by api.ts
      const response = await api.post("/analyze", {
        url,
      });

      setResult(response.data.data);

      // Refresh history after successful analysis
      await fetchHistory();
    } catch (err: any) {
      if (err.response?.status === 401) {
        localStorage.removeItem("access_token");
        setIsAuthenticated(false);
        setError("Your session has expired. Please login again.");
      } else {
        setError(
          err.response?.data?.message ||
            "Something went wrong while analyzing the URL."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  // -----------------------------
  // Initial history check
  // -----------------------------
  useEffect(() => {
    if (isAuthenticated) {
      fetchHistory();
    }
  }, [isAuthenticated]);

  // -----------------------------
  // UI
  // -----------------------------
  return (
    <div className="app">
      <header className="navbar">
        <div>
          <h1>WebGuard</h1>
          <span>URL Risk Analyzer</span>
        </div>

        {isAuthenticated && (
          <button
            className="logout-button"
            onClick={handleLogout}
          >
            Logout
          </button>
        )}
      </header>

      {!isAuthenticated ? (
        <div className="auth-container">
          <div className="auth-card">
            <h1>WebGuard</h1>

            <h2>
              {showRegister ? "Create Account" : "Login"}
            </h2>

            {showRegister && (
              <input
                type="text"
                placeholder="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            )}

            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            {authError && (
              <p className="auth-error">{authError}</p>
            )}

            <button
              onClick={
                showRegister ? handleRegister : handleLogin
              }
              disabled={authLoading}
            >
              {authLoading
                ? "Please wait..."
                : showRegister
                ? "Register"
                : "Login"}
            </button>

            <button
              type="button"
              className="auth-switch"
              onClick={() => {
                setShowRegister(!showRegister);
                setAuthError("");
              }}
            >
              {showRegister
                ? "Already have an account? Login"
                : "Don't have an account? Register"}
            </button>
          </div>
        </div>
      ) : (
        <main className="container">
          {/* Analyzer */}
          <section className="hero">
            <h2>Analyze a Website</h2>

            <p>
              Check a URL for suspicious patterns and potential
              security risks.
            </p>

            <div className="analyzer">
              <input
                type="text"
                placeholder="Enter website URL..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    analyzeUrl();
                  }
                }}
              />

              <button
                onClick={analyzeUrl}
                disabled={loading}
              >
                {loading ? "Analyzing..." : "Analyze URL"}
              </button>
            </div>

            {error && <p className="error">{error}</p>}
          </section>

          {/* Analysis Result */}
          {result && (
            <section className="result-card">
              <div className="result-header">
                <div>
                  <p className="label">Analyzed URL</p>
                  <h3>{result.url}</h3>
                </div>

                <div
                  className={`risk ${result.risk_level.toLowerCase()}`}
                >
                  {result.risk_level} Risk
                </div>
              </div>

              <div className="score">
                <span>Risk Score</span>
                <strong>{result.risk_score}/100</strong>
              </div>

              <div className="ai-section">
                <button
                  className="ai-button"
                  onClick={explainWithAI}
                  disabled={aiLoading}
                >
                  {aiLoading
                    ? "Generating Explanation..."
                    : "Explain with AI"}
                </button>

                {aiError && (
                  <p className="ai-error">{aiError}</p>
                )}

                {aiExplanation && (
                  <div className="ai-explanation">
                    <h3>AI Explanation</h3>
                    <p>{aiExplanation}</p>
                  </div>
                )}
              </div>

              {/* Signals */}
              <div className="signals">
                <h3>Detected Signals</h3>

                {result.signals.length === 0 ? (
                  <p>No suspicious signals detected.</p>
                ) : (
                  result.signals.map((signal, index) => (
                    <div
                      className="signal"
                      key={index}
                    >
                      <div>
                        <strong>{signal.name}</strong>

                        {signal.keywords && (
                          <p>
                            Keywords:{" "}
                            {signal.keywords.join(", ")}
                          </p>
                        )}
                      </div>

                      <span>+{signal.points}</span>
                    </div>
                  ))
                )}
              </div>

              {/* Webpage Information */}
              <div className="webpage-info">
                <h3>Webpage Information</h3>

                <div className="webpage-grid">
                  <div>
                    <span>Page Title</span>
                    <strong>
                      {result.webpage?.title || "N/A"}
                    </strong>
                  </div>

                  <div>
                    <span>Forms</span>
                    <strong>
                      {result.webpage?.forms ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Links</span>
                    <strong>
                      {result.webpage?.links ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Images</span>
                    <strong>
                      {result.webpage?.images ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Scripts</span>
                    <strong>
                      {result.webpage?.scripts ?? 0}
                    </strong>
                  </div>

                  <div>
                    <span>Password Fields</span>
                    <strong>
                      {result.webpage?.password_fields ?? 0}
                    </strong>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* Analysis History */}
          <section className="history-section">
            <h2>Analysis History</h2>

            {historyLoading ? (
              <p>Loading history...</p>
            ) : history.length === 0 ? (
              <p>No analyses yet.</p>
            ) : (
              <div className="history-list">
                {history.map((item) => (
                  <div
                    className="history-card"
                    key={item.id}
                  >
                    <div>
                      <h3>
                        {item.page_title ||
                          "Untitled Page"}
                      </h3>

                      <p className="history-url">
                        {item.url}
                      </p>
                    </div>

                    <div className="history-details">
                      <span>
                        Risk: {item.risk_score}
                      </span>

                      <span>
                        Level: {item.risk_level}
                      </span>

                      <span>
                        Forms: {item.forms}
                      </span>

                      <span>
                        Password Fields:{" "}
                        {item.password_fields}
                      </span>
                    </div>

                    <small>
                      {new Date(
                        item.created_at
                      ).toLocaleString()}
                    </small>
                  </div>
                ))}
              </div>
            )}
          </section>
        </main>
      )} 
    </div>
  );
}

export default App; 