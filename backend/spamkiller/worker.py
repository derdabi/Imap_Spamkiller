import asyncio

from .database import SessionLocal, init_db
from .scanner import worker_loop


def main() -> None:
    init_db()
    asyncio.run(worker_loop(SessionLocal))


if __name__ == "__main__":
    main()
