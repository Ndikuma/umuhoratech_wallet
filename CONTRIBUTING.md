# Contributing Guide

Thanks for your interest in contributing! This guide explains how to set up your environment, propose changes, and submit pull requests.

## Development setup

1) Fork and clone
```
git clone https://github.com/<your-username>/<your-fork>.git
cd wallet
```

2) Create a virtualenv and install dependencies
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
```

3) Run tests
```
python manage.py test
```

4) Start the dev server
```
python manage.py runserver
```

## Branching strategy

- main: stable, released code
- feature/<short-name>: feature work
- fix/<short-name>: bug fixes
- docs/<short-name>: documentation-only changes

## Commit messages

Use clear, descriptive messages. Conventional Commits are encouraged:
- feat: add a new feature
- fix: a bug fix
- docs: documentation changes
- refactor: non-feature code changes
- test: adding or updating tests
- chore: tooling, CI, deps, etc.

## Code style

- Follow PEP 8 where practical.
- Prefer type annotations in new/updated code.
- Keep functions cohesive and small.
- Add/extend tests for new behavior.

## Tests

- Unit tests live in each app's tests.py or a tests/ package.
- Add tests for serializers, views, and utilities.
- Use DRF APIClient for endpoint tests.

## Pull Requests

1. Create a topic branch from main.
2. Make your changes with tests.
3. Run the test suite and linting.
4. Push and open a PR against main.
5. Fill out the PR template.

PR checklist
- [ ] Tests added/updated
- [ ] Docs updated (README/docs/wiki)
- [ ] All checks pass locally
- [ ] Small and focused changes

## Reporting issues

Use GitHub Issues and include:
- Steps to reproduce
- Expected vs actual behavior
- Logs/tracebacks if applicable
- Environment details (OS, Python, DB)

## Security

Report security issues privately. Do not open public issues. Email the maintainer or use GitHub security advisories.
