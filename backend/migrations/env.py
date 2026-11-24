from collections.abc import Iterator
from contextlib import contextmanager

from alembic import context
from sqlalchemy import Connection

from app.config import DatabaseSettings
from app.network import repository as _repository  # noqa: F401
from app.storage import Base, sqlite_engine
from app.workflows import store as _workflows  # noqa: F401


@contextmanager
def migration_connection() -> Iterator[Connection]:
    path = DatabaseSettings().database_path
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = sqlite_engine(path)
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


if context.is_offline_mode():
    context.configure(
        dialect_name="sqlite", target_metadata=Base.metadata, transactional_ddl=True
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    with migration_connection() as connection:
        context.configure(
            connection=connection, target_metadata=Base.metadata, transactional_ddl=True
        )
        with context.begin_transaction():
            context.run_migrations()
