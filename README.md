# PreCog Security API

AI-powered security scanning for GitHub repositories.

## Deploy (one command)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/tim777z/precog-api)

```bash
# Or deploy to Fly.io
fly deploy
```

## API

```bash
# Scan a repo
curl -X POST https://your-domain.com/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/tim777z/PreCogSecurity"}'
```

## Pricing

| Plan | Price | Scans |
|------|-------|-------|
| Free | $0/mo | 5 |
| Pro | $29/mo | Unlimited |
| Team | $99/mo | Unlimited + API |

## License

Proprietary — PreCog Security
