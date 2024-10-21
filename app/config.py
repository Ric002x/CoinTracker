import os


class Config:
    JWT_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
    USE_POSTGRESQL = os.environ.get("USE_POSTGRESQL", "0") == "1"
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    if USE_POSTGRESQL:
        SQLALCHEMY_DATABASE_URI = \
            "postgresql+psycopg2://" \
            f"{os.environ.get("DATABASE_USER")}:" \
            f"{os.environ.get("DATABASE_PASSWORD")}" \
            f"@{os.environ.get("DATABASE_HOST")
                }:5432/{os.environ.get("DATABASE_DB")}"
    else:
        SQLALCHEMY_DATABASE_URI = (
            str(os.environ.get("DATABASE_SQLITE")))
