from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import os

from .scanner import SecurityScanner

app = FastAPI(
    title="PreCog Security API",
    description="AI-powered security scanning for code repositories",
    version="1.0.0"
)

scanner = SecurityScanner()

class ScanRequest(BaseModel):
    repo_url: str
    deep: bool = False

class ScanResponse(BaseModel):
    repo_url: str
    score: int
    findings_count: int
    files_scanned: int
    categories: dict
    summary: str
    findings: list

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return """<!DOCTYPE html>
<html>
<head>
    <title>PreCog Security API</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; color: #333; }
        .hero { background: linear-gradient(135deg, #1a1a2e, #0f3460); color: white; padding: 80px 20px; text-align: center; }
        .hero h1 { font-size: 2.5rem; margin-bottom: 15px; }
        .hero p { font-size: 1.1rem; opacity: 0.9; }
        .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
        .pricing { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 40px 0; }
        .plan { border: 2px solid #eee; border-radius: 10px; padding: 30px; text-align: center; }
        .plan.featured { border-color: #e94560; transform: scale(1.05); }
        .plan h3 { margin-bottom: 10px; }
        .plan .price { font-size: 2rem; color: #0f3460; margin: 15px 0; }
        .plan ul { text-align: left; margin: 20px 0; }
        .plan li { padding: 5px 0; }
        .cta { display: inline-block; background: #e94560; color: white; padding: 12px 30px; border-radius: 5px; text-decoration: none; font-weight: bold; margin-top: 15px; }
        .cta:hover { background: #c73e54; }
        .docs { background: #f8f9fa; padding: 40px 20px; }
        code { background: #1a1a2e; color: #4ade80; padding: 2px 6px; border-radius: 4px; }
        pre { background: #1a1a2e; color: #4ade80; padding: 20px; border-radius: 8px; overflow-x: auto; margin: 15px 0; }
        .footer { background: #1a1a2e; color: white; text-align: center; padding: 30px; }
    </style>
</head>
<body>
    <div class="hero">
        <h1>PreCog Security API</h1>
        <p>Scan any GitHub repo for security vulnerabilities in seconds. AI-powered analysis.</p>
    </div>
    <div class="container">
        <h2>How It Works</h2>
        <p>POST a GitHub URL. Get a security report. That's it.</p>
        <pre>curl -X POST https://api.precogsecurity.io/scan \\
  -H "Content-Type: application/json" \\
  -d '{"repo_url": "https://github.com/user/repo"}'</pre>
        <h2>Response</h2>
        <pre>{
  "score": 72,
  "grade": "C",
  "findings": [...],
  "summary": "Score: 72/100 (Grade C). 12 findings across 45 files."
}</pre>
    </div>
    <div class="container">
        <div class="pricing">
            <div class="plan">
                <h3>Free</h3>
                <div class="price">$0<small>/mo</small></div>
                <ul>
                    <li>5 scans/month</li>
                    <li>Public repos only</li>
                    <li>Basic report</li>
                </ul>
                <a href="https://github.com/PreCogSecurity" class="cta">Get Started</a>
            </div>
            <div class="plan featured">
                <h3>Pro</h3>
                <div class="price">$29<small>/mo</small></div>
                <ul>
                    <li>Unlimited scans</li>
                    <li>Public + Private repos</li>
                    <li>Deep analysis</li>
                    <li>CI/CD integration</li>
                    <li>Email reports</li>
                </ul>
                <a href="mailto:timlangeveldt@gmail.com?subject=PreCog%20Pro%20Subscription" class="cta">Subscribe</a>
            </div>
            <div class="plan">
                <h3>Team</h3>
                <div class="price">$99<small>/mo</small></div>
                <ul>
                    <li>Everything in Pro</li>
                    <li>5 team members</li>
                    <li>API access</li>
                    <li>Priority support</li>
                    <li>Custom rules</li>
                </ul>
                <a href="mailto:timlangeveldt@gmail.com?subject=PreCog%20Team%20Subscription" class="cta">Contact Us</a>
            </div>
        </div>
    </div>
    <div class="docs">
        <div class="container">
            <h2>API Documentation</h2>
            <p><strong>Endpoint:</strong> <code>POST /scan</code></p>
            <p><strong>Body:</strong> <code>{"repo_url": "https://github.com/owner/repo"}</code></p>
            <p><strong>Auth:</strong> API key in <code>X-API-Key</code> header (Pro/Team)</p>
            <p><strong>Rate Limit:</strong> 5 scans/month (Free), Unlimited (Pro/Team)</p>
        </div>
    </div>
    <div class="footer">
        <p>Contact: <a href="mailto:timlangeveldt@gmail.com" style="color:#e94560">timlangeveldt@gmail.com</a></p>
        <p>&copy; 2026 PreCog Security</p>
    </div>
</body>
</html>"""

@app.post("/scan", response_model=ScanResponse)
async def scan_repo(req: ScanRequest):
    if not req.repo_url.startswith("https://github.com/"):
        raise HTTPException(400, "Only GitHub URLs supported")
    
    result = scanner.scan_repo(req.repo_url)
    
    if "error" in result:
        raise HTTPException(500, result["error"])
    
    return ScanResponse(
        repo_url=result["repo_url"],
        score=result["score"],
        findings_count=len(result["findings"]),
        files_scanned=result["files_scanned"],
        categories=result["categories"],
        summary=result["summary"],
        findings=result["findings"]
    )

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
