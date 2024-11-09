import datetime
import os
import sqlite3
from contextlib import closing
from pathlib import PurePath

from blint_db import (BLINTDB_LOCATION, COMMON_CONNECTION, DEBUG_MODE,
                      SQLITE_TIMEOUT)


def use_existing_connection(connection=None):  # Decorator now accepts connection
    """
    Decorator to use an existing connection when BLINTDB_LOCATION is ':memory:'.
    The connection should be passed as an argument to the decorator itself.
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            if connection:
                with closing(connection.cursor()) as c:
                    if len(args) > 1:
                        c.execute(args[0], args[1])
                    else:
                        c.execute(args[0])
                    res = c.fetchall()
                connection.commit()
                return res
            return func(*args, **kwargs)

        return wrapper

    return decorator


@use_existing_connection(connection=COMMON_CONNECTION)
def execute_statement(statement, arguments=False):
    with closing(
        sqlite3.connect(BLINTDB_LOCATION, timeout=SQLITE_TIMEOUT)
    ) as connection:
        with closing(connection.cursor()) as c:
            if arguments:
                c.execute(statement, arguments)
            else:
                c.execute(statement)
            res = c.fetchall()
        connection.commit()
    return res


def create_database():
    # TODO: make purl unique

    pragma_sync = execute_statement("PRAGMA synchronous = 'OFF';")
    pragma_jm = execute_statement("PRAGMA journal_mode = 'MEMORY';")
    pragma_ts = execute_statement("PRAGMA temp_store = 'MEMORY';")

    projects_table = execute_statement(
        """
        CREATE TABLE IF NOT EXISTS Projects (
            pid     INTEGER PRIMARY KEY AUTOINCREMENT,
            pname   VARCHAR(255) UNIQUE,
            purl    VARCHAR(255),
            cbom    BLOB
        );
        """
    )

    binaries_table = execute_statement(
        """
        CREATE TABLE IF NOT EXISTS Binaries (
            bid     INTEGER PRIMARY KEY AUTOINCREMENT,
            pid     INTEGER,
            bname   VARCHAR(500),
            bbom    BLOB,
            FOREIGN KEY (pid) REFERENCES Projects(pid)
        );
        """
    )

    exports_table = execute_statement(
        """
        CREATE TABLE IF NOT EXISTS Exports (
            infunc  VARCHAR(255) PRIMARY KEY
        );
        """
    )

    binary_exports_table = execute_statement(
        """
        CREATE TABLE IF NOT EXISTS BinariesExports (
            bid INTEGER,
            eid INTEGER,
            PRIMARY KEY (bid, eid),
            FOREIGN KEY (bid) REFERENCES Binaries(bid),
            FOREIGN KEY (eid) REFERENCES Exports(eid)
        );
        """
    )

    index_table = execute_statement(
        """
        CREATE INDEX IF NOT EXISTS export_name_index ON Exports (infunc);
        """
    )

    if DEBUG_MODE:
        print(
            projects_table,
            binaries_table,
            exports_table,
            binary_exports_table,
            index_table,
            pragma_jm,
            pragma_sync,
            pragma_ts,
        )


def clear_sqlite_database():
    if os.path.exists(BLINTDB_LOCATION):
        if os.path.isfile(BLINTDB_LOCATION):
            os.remove(BLINTDB_LOCATION)


def store_sbom_in_sqlite(purl, sbom):
    execute_statement(
        "INSERT INTO blintsboms VALUES (?, ?, jsonb(?))",
        (purl, datetime.datetime.now(), sbom),
    )


# add project
def add_projects(project_name, purl=None, cbom=None):
    execute_statement(
        "INSERT INTO Projects (pname, purl, cbom) VALUES (?, ?, ?)",
        (project_name, purl, cbom),
    )

    # retrieve pid
    res = execute_statement("SELECT pid FROM Projects WHERE pname=?", (project_name,))

    return res[0][0]


# add binary
def add_binary(binary_file_path, project_id, blint_bom=None, split_word="subprojects/"):
    if isinstance(binary_file_path, PurePath):
        binary_file_path = str(binary_file_path)

    # truncate the binary file path
    binary_file_path = binary_file_path.split(split_word)[1]

    execute_statement(
        "INSERT INTO Binaries (pid, bname, bbom) VALUES (?, ?, ?)",
        (project_id, binary_file_path, blint_bom),
    )

    # retrieve bid

    res = execute_statement(
        "SELECT bid FROM Binaries WHERE bname=?", (binary_file_path,)
    )

    return res[0][0]


# add export
def add_binary_export(infunc, bid):

    def _fetch_bin_exists(bid, eid):

        res = execute_statement(
            "SELECT bid FROM BinariesExports WHERE bid=? and eid=?", (bid, eid)
        )
        if res:
            res = res[0][0]
            return res == bid

    def _fetch_infunc_row(infunc):
        res = execute_statement("SELECT rowid FROM Exports WHERE infunc=?", (infunc,))
        return res

    pre_existing = _fetch_infunc_row(infunc)
    if pre_existing:
        eid = pre_existing[0][0]
        if not _fetch_bin_exists(bid, eid):
            execute_statement(
                "INSERT INTO BinariesExports (bid, eid) VALUES (?, ?)",
                (bid, eid),
            )

        return 0

    execute_statement("INSERT INTO Exports (infunc) VALUES (?)", (infunc,))

    eid = _fetch_infunc_row(infunc)[0][0]

    execute_statement(
        "INSERT INTO BinariesExports (bid, eid) VALUES (?, ?)", (bid, eid)
    )
