# Deployment

Production checklist
- DEBUG=false
- SECRET_KEY set
- ALLOWED_HOSTS configured
- HTTPS
- Postgres recommended
- Collect static: `python manage.py collectstatic --noinput`
- Run migrations: `python manage.py migrate --noinput`

Example run command
```
GUNICORN_CMD_ARGS="--bind 0.0.0.0:8000 --workers 3" gunicorn wallet.wsgi:application
```
