# API Reference

Visit Swagger UI at /docs/ for live schema. Highlights:

Auth
- POST /auth/register/
- POST /auth/login/
- POST /auth/logout/

User
- GET  /user/
- GET  /user/profile/
- POST /user/change_password/

Wallet
- GET  /wallet/
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
- GET  /transaction/
- GET  /transaction/recents/
- POST /transaction/send/
- POST /transaction/sync/
- GET  /transaction/track/<txid>/

Providers & Orders
- GET  /providers/
- GET  /providers/buy/
- GET  /providers/sell/
- POST /providers/buy/calculate-fee/
- GET  /orders/
- POST /orders/
