"""
secure.storage — everything related to reading and writing the local
SQLite database.

    database.py -> low-level connection handling + schema creation
    models.py   -> small, friendly functions for reading/writing rows

Nothing outside this package should run raw SQL directly; go through
the functions in models.py instead. That keeps the database schema in
one place, which matters once you start adding real security features
that touch the database from many parts of the app.
"""
