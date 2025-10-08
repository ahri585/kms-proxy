import os

class Config:
    # PostgreSQL 연결 (환경변수 없을 시 기본값 사용)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://lockument_app:1234qwer@db:5432/lockument_db"
    )

    # SQLAlchemy 이벤트 추적 끄기 (불필요한 경고 방지)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT나 세션용 시크릿 키 (없을 시 기본값)
    SECRET_KEY = os.getenv("JWT_SECRET", "change_this_in_prod_please")

