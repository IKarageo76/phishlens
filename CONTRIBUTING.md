# Contributing

Thanks for helping. Small, focused pull requests are easiest to review.

1. Fork the repo and create a branch: `git checkout -b feat/otx-source`.
2. Backend: `cd backend && pip install -r requirements-dev.txt`, then `ruff check app tests && pytest` must pass.
3. Frontend: `cd frontend && npm install && npm run build` must pass.
4. Add or update tests. Tests never call real APIs: mock HTTP with `respx`.
5. Never commit real phishing emails, client data or API keys. Sample emails must be fictitious.

Good first contributions:

- **A new intelligence source.** See [docs/adding-a-source.md](docs/adding-a-source.md).
- **Domains** for the lists in `backend/app/data/` (free-mail, disposable, shorteners, brands).
- **Labelled sample emails**, with expected verdicts, to tune `weights.yaml`.
