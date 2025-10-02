# Getting Started

A concise version of the docs/getting-started.md for the GitHub Wiki.

1) Clone and setup
```
git clone <your-repo-url>.git
cd wallet
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
```

2) Run
```
python manage.py runserver
```

3) Browse
- /docs/ (Swagger)
- /redoc/
- /schema/
- /admin/
