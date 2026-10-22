FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml ./
COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic
RUN pip install .
EXPOSE 8003
# Apply migrations, then start. Defaults (admin app, ERP roles) are seeded on startup.
CMD ["sh", "-c", "alembic upgrade head && uvicorn mango_auth.main:app_factory --factory --host 0.0.0.0 --port 8003"]
