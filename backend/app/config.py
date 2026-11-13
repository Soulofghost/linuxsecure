import os

PORT = int(os.getenv("LINUXSECURE_PORT", "8000"))
DB_PATH = os.getenv("LINUXSECURE_DB_PATH", "backend/data/linuxsecure.db")
