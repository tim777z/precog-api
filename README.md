# PreCog Security API

AI-powered security scanning for GitHub repositories.

## Quick Start

```bash
# Run locally
pip install -e .
uvicorn app.main:app --reload

# Scan a repo
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/tim777z/PreCogSecurity"}'
```

## Deploy

```bash
# Docker
docker build -t precog-api .
docker run -p 8000:8000 precog-api

# Or deploy to Render/Railway/Fly.io
```

## Pricing

| Plan | Price | Scans | Repos |
|------|-------|-------|-------|
| Free | $0/mo | 5 | Public only |
| Pro | $29/mo | Unlimited | Public + Private |
| Team | $99/mo | Unlimited | + API + Support |

## Contact

timlangeveldt@gmail.com

## License

Proprietary - PreCog Security
