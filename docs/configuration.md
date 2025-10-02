# Configuration

All configuration defaults live in wallet/wallet/settings.py. Use environment variables for production.

## Essential settings

- SECRET_KEY: replace in production
- DEBUG: set to false in production
- ALLOWED_HOSTS: list of allowed hosts (or '*')
- DATABASES: override with a prod DB (e.g., Postgres)
- CORS_ALLOWED_ORIGINS: add your frontends

## Project-specific

- WALLET_SETTINGS.MIN_TRANSACTION_AMOUNT: minimum send amount in BTC
- FEE_ADDRESS: Bitcoin address for service fees (replace placeholder)
- BITCOINLIB_DB: path to a bitcoinlib DB file used by the service layer

## Environment variables (recommended)

- DJANGO_SECRET_KEY
- DJANGO_DEBUG
- DJANGO_ALLOWED_HOSTS
- CORS_ALLOWED_ORIGINS
- DATABASE_URL (if using dj-database-url or similar)

## Static/Media

- STATIC_URL / STATIC_ROOT
- MEDIA_URL / MEDIA_ROOT

## DRF

Token auth enabled by default:
```
Authorization: Token <token>
```

OpenAPI:
- DEFAULT_SCHEMA_CLASS: drf_spectacular.openapi.AutoSchema
- Endpoints: /schema/, /docs/, /redoc/
