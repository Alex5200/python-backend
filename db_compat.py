from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def ensure_user_role_column(engine: Engine) -> None:
    inspector = inspect(engine)
    try:
        columns = inspector.get_columns('users')
        names = {c['name'] for c in columns}
    except Exception:
        # Если таблицы users нет, create_all создаст её — тут делать нечего
        return

    if 'role_id' not in names:
        with engine.connect() as conn:
            conn.execute(text('ALTER TABLE users ADD COLUMN role_id uuid NULL'))
            conn.execute(text('ALTER TABLE users ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_users_role_id ON users (role_id)'))
            conn.commit()

