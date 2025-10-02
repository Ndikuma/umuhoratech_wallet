# Development

## Test suite
Run all tests:
```
python manage.py test
```

## Suggested tools
- black, isort, ruff for lint/format
- pre-commit hooks

Example pre-commit config (create .pre-commit-config.yaml):
```
repos:
  - repo: https://github.com/psf/black
    rev: 24.8.0
    hooks:
      - id: black
  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
```
Then:
```
pip install pre-commit
pre-commit install
```

## Running locally
```
python manage.py runserver
```

## Tips
- Use DRF's APIClient for tests
- Use factories or fixtures for users/wallets/orders
- Keep endpoints small and well-documented (drf-spectacular annotations)
