# Getting Started

## Prerequisites
- Python 3.11+
- pip / venv

## Setup

1) Clone and enter the project directory
```
git clone <your-repo-url>.git
cd wallet
```

2) Create a virtual environment and activate
```
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

3) Install dependencies
```
pip install -r requirements.txt
```

4) Initialize database and superuser
```
python manage.py migrate
python manage.py createsuperuser
```

5) Run the app
```
python manage.py runserver
```

Open http://127.0.0.1:8000/
- Admin:           /admin/
- Swagger:         /docs/
- Redoc:           /redoc/
- OpenAPI schema:  /schema/
