from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _engine_args() -> dict:
    url = get_settings().resolved_database_url
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False, "timeout": 30}}
    return {}


engine = create_engine(get_settings().resolved_database_url, future=True, **_engine_args())


if get_settings().resolved_database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def init_db() -> None:
    get_settings().data_dir.mkdir(parents=True, exist_ok=True)
    import spamkiller.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_schema(engine)


def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def _migrate_sqlite_schema(target_engine: Engine) -> None:
    # TODO: Remove this helper once the project is open-sourced and a proper migration
    # system is introduced.
    if not str(target_engine.url).startswith("sqlite"):
        return

    with target_engine.begin() as connection:
        inspector = inspect(connection)
        existing_tables = set(inspector.get_table_names())
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing_columns or column.primary_key:
                    continue
                connection.execute(text(f"ALTER TABLE {_quote_identifier(table.name)} ADD COLUMN {_sqlite_column_definition(target_engine, column)}"))
                default = _scalar_default(column)
                if default is not None:
                    connection.execute(
                        text(f"UPDATE {_quote_identifier(table.name)} SET {_quote_identifier(column.name)} = :default WHERE {_quote_identifier(column.name)} IS NULL"),
                        {"default": default},
                    )


def _sqlite_column_definition(target_engine: Engine, column) -> str:
    column_type = column.type.compile(dialect=target_engine.dialect)
    return f"{_quote_identifier(column.name)} {column_type}"


def _scalar_default(column):
    if column.default is None or not column.default.is_scalar:
        return None
    value = column.default.arg
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (str, int, float)):
        return value
    return None


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'
