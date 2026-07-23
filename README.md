# VACE - Vulnerability Assessment Consolidation Engine

## Database Migrations

The backend uses [Alembic](https://alembic.sqlalchemy.org/) to manage PostgreSQL schema changes for the SQLAlchemy models in `backend/app/models/`.

Run commands from the `backend/` directory (with the virtualenv activated), so `DATABASE_URL` is picked up from `app.config.settings` / `.env`.

**Apply migrations (bring the DB schema up to date):**

```bash
cd backend
alembic upgrade head
```

**Generate a new migration after changing a model:**

```bash
cd backend
alembic revision --autogenerate -m "describe your change"
```

Review the generated file in `backend/alembic/versions/` before applying it, then run `alembic upgrade head`.
