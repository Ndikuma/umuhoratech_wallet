# Bitcoin Mini Wallet API (Django + DRF)

Open-source Bitcoin wallet REST API built with Django and Django REST Framework. It provides user authentication, wallet lifecycle management (create/restore/backup), address generation, QR codes, balances, and transactions, plus a simple provider/order module for buy/sell flows. API schema and interactive docs are available via Swagger and Redoc.

- Project status: Alpha (testnet by default)
- Stack: Python, Django 5, DRF, drf-spectacular
- Apps: walletapp (wallet + tx), orders (providers + orders)


## Features

- Authentication (token-based)
- User profile and password change
- Wallet lifecycle:
  - Generate mnemonic (12/24 words)
  - Create wallet (auto-generate mnemonic if missing)
  - Restore wallet (mnemonic or private key)
  - Backup (WIF)
- Address management:
  - Generate new receiving address (with optional label)
  - Generate QR code for receiving
- Balance:
  - Get and format balances; USD/BIF helpers in serializers
- Transactions:
  - List and recent
  - Estimate fee and sendable amount
  - Send BTC
  - Sync from network
  - Track by TXID
- Providers/Orders module:
  - List providers, filter by buy/sell capability
  - Calculate provider fee and convert fiat (USD/BIF) to BTC
- OpenAPI schema + Swagger UI + Redoc powered by drf-spectacular


## Quickstart

Prerequisites
- Python 3.11+
- pip/venv

1) Clone and enter the project directory

```
git clone <your-fork-or-repo-url>.git
cd wallet
```

2) Create and activate virtualenv

```
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

3) Install dependencies

```
pip install -r requirements.txt
```

4) Apply migrations and create a superuser

```
python manage.py migrate
python manage.py createsuperuser
```

5) Run the development server

```
python manage.py runserver
```

The API should be available at http://127.0.0.1:8000/

- Admin:           /admin/
- API root:        /
- API docs (Swagger): /docs/
- API docs (Redoc):   /redoc/
- OpenAPI schema:     /schema/


## Configuration

Important settings are in wallet/wallet/settings.py. For production, use environment variables and never hardcode secrets.

Recommended environment variables
- DJANGO_SECRET_KEY: Django secret key
- DJANGO_DEBUG: false in production
- DJANGO_ALLOWED_HOSTS: comma-separated hostnames
- CORS_ALLOWED_ORIGINS: comma-separated URLs allowed to call the API
- DATABASE_URL: production database URL (if not using SQLite)

Project-specific settings
- WALLET_SETTINGS.MIN_TRANSACTION_AMOUNT: minimal BTC amount allowed (Decimal)
- FEE_ADDRESS: your service fee Bitcoin address (string). Replace placeholder.
- BITCOINLIB_DB: path to bitcoinlib DB file (defaults to bitcoinlib.db in project root)

CORS
- Configured in settings.py (CORS_ALLOWED_ORIGINS). Adjust for your frontend domains.

Static and media
- STATIC_URL = "static/", collected into staticfiles/ for deployment
- MEDIA_URL = "media/"


## Auth & Headers

- Authentication: Token-based (DRF Token)
- Header: `Authorization: Token <your-token>`

Endpoints to obtain token
- POST /auth/register/ → returns token
- POST /auth/login/ → returns token
- POST /auth/logout/ → invalidates token


## API Overview

Base path: /

Auth
- POST /auth/register/
- POST /auth/login/
- POST /auth/logout/

User
- GET  /user/               → list (current user only due to queryset override)
- GET  /user/profile/
- POST /user/change_password/

Wallet
- GET  /wallet/             → list (current user wallet)
- POST /wallet/create_wallet/
- POST /wallet/generate_mnemonic/
- POST /wallet/verify_mnemonic/
- POST /wallet/restore/
- GET  /wallet/balance/
- GET  /wallet/backup/
- POST /wallet/generate_address/
- POST /wallet/generate_qr_code/
- POST /wallet/estimate_fee/

Transactions
- GET  /transaction/        → list (syncs before listing)
- GET  /transaction/recents/
- POST /transaction/send/
- POST /transaction/sync/
- GET  /transaction/track/<txid>/

Providers & Orders
- GET  /providers/
- GET  /providers/buy/
- GET  /providers/sell/
- POST /providers/buy/calculate-fee/  → body: { provider_id, amount, currency: "USD"|"BIF" }
- GET  /orders/
- POST /orders/

API Schema & Docs
- GET /schema/ → OpenAPI JSON
- GET /docs/   → Swagger UI
- GET /redoc/  → Redoc UI


## Sample Requests

Register
```
POST /auth/register/
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "StrongPass123!"
}
```

Login
```
POST /auth/login/
{
  "username": "alice",
  "password": "StrongPass123!"
}
```

Create wallet
```
POST /wallet/create_wallet/
Authorization: Token <token>
{
  "network": "testnet"  // default if omitted
}
```

Send BTC
```
POST /transaction/send/
Authorization: Token <token>
{
  "to_address": "<valid-btc-address>",
  "amount": "0.0001"
}
```

Calculate provider fee
```
POST /providers/buy/calculate-fee/
{
  "provider_id": 1,
  "amount": "100",
  "currency": "USD" // or "BIF"
}
```


## Security Notes

- Do not expose your WIF, mnemonic, or private keys. Handle secrets off-server.
- Replace FEE_ADDRESS with a secure address you control.
- Use HTTPS in production and set DJANGO_DEBUG=false.
- Rotate tokens and secrets regularly.
- Consider rate limiting and per-user throttles for sensitive endpoints.


## Development

Run tests
```
python manage.py test
```

Lint/format (example tools you can add):
- ruff, black, isort


## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines and project conventions.

- Fork the repo and create feature branches
- Write tests where appropriate
- Keep PRs focused and small
- Follow commit message conventions (e.g., Conventional Commits)

See also: CODE_OF_CONDUCT.md


## License

This project is licensed under the MIT License. See LICENSE for details.


## Acknowledgements

- Django, Django REST Framework
- drf-spectacular for OpenAPI generation
- bitcoinlib and related tooling


## Links

- Swagger UI: /docs/
- Redoc UI: /redoc/
- OpenAPI schema: /schema/
