import os
from dotenv import load_dotenv

# загружаем переменные из .env файла
load_dotenv()

# режим работы приложения
MODE = os.getenv("MODE", "DEV")

# данные для доступа к документации
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret123")

# проверяем корректности MODE
if MODE not in ["DEV", "PROD"]:
    raise ValueError(f"Invalid MODE: {MODE}. Must be DEV or PROD")