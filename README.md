# SecureShare — Blockchain-Inspired File Integrity Ledger

BCA Minor Project · Group No. 004

Upload a file and it gets a SHA-256 fingerprint. Anyone holding that fingerprint (hash) can verify the file is genuine or download the original. Optional accounts (mobile number + password) keep a personal list of your uploads.

## Features

- Upload any file (max 10 MB) — hashed with SHA-256
- Verify a file by its hash
- Download a file using only its hash
- Optional simple login (mobile number + password); guests can use everything else without an account
- Passwords stored as salted PBKDF2-SHA256 hashes, never as plain text
- Account reset (clears your files, keeps your login) — needs your password

## Run on your own computer

```
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8000/

## Put it live (Render, free plan)

1. Upload this folder's contents to a new GitHub repository.
2. On render.com: New + → Web Service → pick that repository.
3. Language: **Python 3** · Build Command: `pip install -r requirements.txt` · Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT` · Instance type: **Free**.
4. Click Create Web Service and wait for the build to finish — your public link ends in `.onrender.com`.

Note: on Render's free plan the service goes to sleep when idle and its local files are wiped when it restarts, so accounts and uploads do not last. Fine for a demo — register and upload shortly before presenting.

## Project structure

```
app.py             FastAPI backend: routes, login, hashing, upload limit
models.py          Database tables (SQLAlchemy)
static/index.html  The website (frontend)
requirements.txt   Python packages
```

## Team

| Roll No. | Name | Role |
|---|---|---|
| 241013106104 | Mohd Hashir | Backend |
| 241013106101 | Md Anas | Frontend |
| 241013106107 | Naman Nain | Hashing |
| 241013106085 | Krishna Gola | Database |

BCA, Batch 2024–2027, 5th Semester · Greater Noida Institute of Management (GNIM-1013) · Chaudhary Charan Singh University, Meerut
