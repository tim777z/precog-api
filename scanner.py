import subprocess
import tempfile
import os
import json
from pathlib import Path
from typing import Dict, List, Optional
import git


class SecurityScanner:
    def __init__(self):
        self.findings = []
        self.score = 100
        
    def scan_repo(self, repo_url: str) -> Dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                repo = git.Repo.clone_from(repo_url, tmpdir, depth=1)
            except Exception as e:
                return {"error": f"Could not clone repo: {str(e)}"}
            
            results = {
                "repo_url": repo_url,
                "files_scanned": 0,
                "findings": [],
                "score": 100,
                "categories": {},
                "summary": ""
            }
            
            py_files = list(Path(tmpdir).rglob("*.py"))
            results["files_scanned"] = len(py_files)
            
            if py_files:
                bandit_results = self._run_bandit(tmpdir)
                results["findings"].extend(bandit_results)
            
            js_files = list(Path(tmpdir).rglob("*.js")) + list(Path(tmpdir).rglob("*.ts"))
            if js_files:
                npm_audit = self._run_npm_audit(tmpdir)
                results["findings"].extend(npm_audit)
            
            secret_results = self._scan_secrets(tmpdir)
            results["findings"].extend(secret_results)
            
            dep_results = self._check_dependencies(tmpdir)
            results["findings"].extend(dep_results)
            
            for f in results["findings"]:
                cat = f.get("category", "other")
                results["categories"][cat] = results["categories"].get(cat, 0) + 1
            
            critical = sum(1 for f in results["findings"] if f.get("severity") == "critical")
            high = sum(1 for f in results["findings"] if f.get("severity") == "high")
            medium = sum(1 for f in results["findings"] if f.get("severity") == "medium")
            
            results["score"] = max(0, 100 - (critical * 25) - (high * 10) - (medium * 3))
            results["summary"] = self._generate_summary(results)
            
            return results
    
    def _run_bandit(self, repo_path: str) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for item in data.get("results", []):
                    findings.append({
                        "tool": "bandit",
                        "file": item.get("filename", "").replace(repo_path + "/", ""),
                        "line": item.get("line_number"),
                        "severity": item.get("issue_severity", "").lower(),
                        "confidence": item.get("issue_confidence", "").lower(),
                        "message": item.get("issue_text", ""),
                        "category": "security",
                        "cwe": item.get("issue_cwe", {}).get("id", "")
                    })
        except Exception:
            pass
        return findings
    
    def _run_npm_audit(self, repo_path: str) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=repo_path, capture_output=True, text=True, timeout=60
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", {}).items():
                    findings.append({
                        "tool": "npm-audit",
                        "file": "package.json",
                        "severity": vuln[1].get("severity", "medium"),
                        "message": f"{vuln[0]}: {vuln[1].get('title', '')}",
                        "category": "dependency"
                    })
        except Exception:
            pass
        return findings
    
    def _scan_secrets(self, repo_path: str) -> List[Dict]:
        findings = []
        patterns = {
            "api_key": ["api[_-]?key", "apikey"],
            "password": ["password", "passwd", "pwd"],
            "token": ["token", "bearer", "auth"],
            "secret": ["secret", "private[_-]?key"],
            "aws": ["AKIA", "aws[_-]?access"],
            "github": ["ghp_", "github[_-]?token"],
        }
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "__pycache__"]]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read()
                    for secret_type, pats in patterns.items():
                        for pat in pats:
                            if pat.lower() in content.lower():
                                findings.append({
                                    "tool": "secret-scan",
                                    "file": fpath.replace(repo_path + "/", ""),
                                    "severity": "critical" if secret_type in ["api_key", "secret", "aws", "github"] else "high",
                                    "message": f"Potential {secret_type} detected",
                                    "category": "secrets"
                                })
                                break
                except Exception:
                    pass
        return findings
    
    def _check_dependencies(self, repo_path: str) -> List[Dict]:
        findings = []
        req_file = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_file):
            with open(req_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "==" not in line and ">=" not in line:
                            findings.append({
                                "tool": "dep-check",
                                "file": "requirements.txt",
                                "severity": "medium",
                                "message": f"Unpinned dependency: {line}",
                                "category": "dependency"
                            })
        return findings
    
    def _generate_summary(self, results: Dict) -> str:
        score = results["score"]
        if score >= 90:
            grade = "A"
            desc = "Excellent security posture"
        elif score >= 75:
            grade = "B"
            desc = "Good, some improvements needed"
        elif score >= 60:
            grade = "C"
            desc = "Moderate risk, action recommended"
        elif score >= 40:
            grade = "D"
            desc = "Significant security concerns"
        else:
            grade = "F"
            desc = "Critical security issues found"
        
        return f"Score: {score}/100 (Grade {grade}). {desc}. {len(results['findings'])} findings across {results['files_scanned']} files."
