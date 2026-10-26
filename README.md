# Messenger Dashboard (configuration-only)

This Flask app provides a password-protected dashboard for saved settings, reply-rule configuration, theme preferences, and activity logs.

**Important limitation:** this project does not connect to Messenger or send replies. Group-name and nickname forms only record requests. The cookie JSON panel checks syntax and basic structure only; never paste real session cookies into it.

## Deploy on Render

1. Upload these files to a GitHub repository: `app.py`, `requirements.txt`, and `Procfile`.
2. In Render, create a **New Web Service** connected to that repository.
3. Use the following settings (the included `Procfile` also specifies the start command):
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
4. In the service's **Environment** settings, add:
   - `SECRET_KEY`: a new random secret (generate with `python -c "import secrets; print(secrets.token_hex(32))"` on a computer with Python, or use a trusted password manager's random generator).
   - `ADMIN_PASSWORD`: a strong, unique dashboard password.
   - `COOKIE_SECURE`: `1` for HTTPS (the default).
5. Optional persistence: if your Render plan supports persistent disks, attach one and mount it at `/var/data`, then add `DB_PATH=/var/data/dashboard.db`. Without a persistent disk, SQLite data may be lost when the service is replaced or its filesystem resets. Do not set `DB_PATH` to `/var/data/dashboard.db` unless that disk is actually attached.
6. Save and deploy. Open the Render URL and sign in with the `ADMIN_PASSWORD` value.

## Troubleshooting `KeyError` / startup failures

- Check the Render **Logs** for the complete traceback and confirm the latest deployment succeeded.
- Ensure `SECRET_KEY` and `ADMIN_PASSWORD` exist under the service's **Environment** settings; do not include quotes in their values. The app intentionally stops with a clear `RuntimeError` if either is missing.
- Use the start command `gunicorn app:app` and ensure the repository root contains `app.py`, `requirements.txt`, and `Procfile`.
- If the traceback still says `KeyError`, inspect the exact key named in the traceback; that may indicate Render is running a different/older commit than this ZIP.
- Never paste passwords, secret keys, or session cookies into logs or support chats.

## Local run

Set `SECRET_KEY` and `ADMIN_PASSWORD` in your shell environment, then run:

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Files

- `app.py`: Flask app and SQLite schema initialization.
- `requirements.txt`: Python dependencies.
- `Procfile`: Gunicorn start command.
