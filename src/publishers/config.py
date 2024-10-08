import os
from dotenv import load_dotenv

load_dotenv()

class Config(object):

    def read_secret(secret_name):
        file_path = f"/run/secrets/{secret_name}"
        try:
            with open(file_path, "r") as secret_file:
                return secret_file.read().strip()
        except FileNotFoundError:
            raise RuntimeError(f"Secret '{secret_name}' not found.")


    API_KEY = read_secret("api_key")
    EMAIL_USER = os.getenv("EMAIL_USER")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    EMAIL_SEND = os.getenv("EMAIL_SEND")
