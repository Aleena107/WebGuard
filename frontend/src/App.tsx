import { useState } from "react";
import axios from "axios";
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

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/analyze",
        {
          url: url.trim(),
        }
      );

      setResult(response.data.data);
    } catch (err: any) {
      setError(
        err.response?.data?.message ||
          "Something went wrong while analyzing the URL."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="navbar">
        <h1>WebGuard</h1>
        <span>URL Risk Analyzer</span>
      </header>

      <main className="container">
        <section className="hero">
          <h2>Analyze a Website</h2>
          <p>
            Check a URL for suspicious patterns and potential security risks.
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

            <button onClick={analyzeUrl} disabled={loading}>
              {loading ? "Analyzing..." : "Analyze URL"}
            </button>
          </div>

          {error && <p className="error">{error}</p>}
        </section>

        {result && (
          <section className="result-card">
            <div className="result-header">
              <div>
                <p className="label">Analyzed URL</p>
                <h3>{result.url}</h3>
              </div>

              <div className={`risk ${result.risk_level.toLowerCase()}`}>
                {result.risk_level} Risk
              </div>
            </div>

            <div className="score">
              <span>Risk Score</span>
              <strong>{result.risk_score}/100</strong>
            </div>

            <div className="signals">
              <h3>Detected Signals</h3>

              {result.signals.length === 0 ? (
                <p>No suspicious signals detected.</p>
              ) : (
                result.signals.map((signal, index) => (
                  <div className="signal" key={index}>
                    <div>
                      <strong>{signal.name}</strong>

                      {signal.keywords && (
                        <p>
                          Keywords: {signal.keywords.join(", ")}
                        </p>
                      )}
                    </div>

                    <span>+{signal.points}</span>
                  </div>
                ))
              )}
            </div>
            <div className="webpage-info">
  <h3>Webpage Information</h3>

  <div className="webpage-grid">
    <div>
      <span>Page Title</span>
      <strong>{result.webpage?.title}</strong>
    </div>

    <div>
      <span>Forms</span>
      <strong>{result.webpage?.forms}</strong>
    </div>

    <div>
      <span>Links</span>
      <strong>{result.webpage?.links}</strong>
    </div>

    <div>
      <span>Images</span>
      <strong>{result.webpage?.images}</strong>
    </div>

    <div>
      <span>Scripts</span>
      <strong>{result.webpage?.scripts}</strong>
    </div>
  </div>
</div>

<div>
  <span>Password Fields</span>
  <strong>{result.webpage?.password_fields}</strong>
</div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;