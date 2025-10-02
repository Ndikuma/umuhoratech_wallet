# Deployment

This project uses Django and DRF and can be deployed to platforms such as Render, Heroku-like PaaS, Docker/Kubernetes, or a VPS.

## Production checklist

- DJANGO_DEBUG=false
- SECRET_KEY set securely
- ALLOWED_HOSTS configured
- HTTPS termination (reverse proxy / load balancer)
- Database (Postgres recommended), run migrations
- Static files served via WhiteNoise or external CDN/bucket
- CORS configured for your frontends
- Logging and monitoring in place

## Example: Gunicorn + Whitenoise

1) Install packages
```
pip install gunicorn whitenoise
```

2) WSGI entry is wallet/wsgi.py

3) Run
```
GUNICORN_CMD_ARGS="--bind 0.0.0.0:8000 --workers 3" gunicorn wallet.wsgi:application
```

## Static files

```
python manage.py collectstatic --noinput
```

## Database migrations
```
python manage.py migrate --noinput
```

## Environment variables

Use a .env file or platform secrets manager to provide:
- DJANGO_SECRET_KEY
- DJANGO_DEBUG
- DJANGO_ALLOWED_HOSTS
- DATABASE_URL (if using Postgres)
- CORS_ALLOWED_ORIGINS
- FEE_ADDRESS
