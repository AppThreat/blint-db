# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import sqlite3
from contextlib import closing
from pathlib import Path

BLINTDB_LOCATION = Path.cwd() / "build" / "blint_working.db"


def get_export_id(export_name):
    with closing(sqlite3.connect(BLINTDB_LOCATION)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT rowid from Exports where infunc=?", (export_name,))
            res = c.fetchall()
        connection.commit()
    if res:
        return res[0][0]
    else:
        return None


def get_bid_using_fid(eid):
    with closing(sqlite3.connect(BLINTDB_LOCATION)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT bid from BinariesExports where eid=?", (eid,))
            res = c.fetchall()
        connection.commit()
    if res:
        return map(lambda x: x[0], res)
    else:
        return None


def get_bname(bid):
    with closing(sqlite3.connect(BLINTDB_LOCATION)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT bname from Binaries where bid=?", (bid,))
            res = c.fetchall()
        connection.commit()
    if res:
        return res[0][0]
    else:
        return None


def get_pname(bid):
    with closing(sqlite3.connect(BLINTDB_LOCATION)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT pid from Binaries where bid=?", (bid,))
            res = c.fetchall()
            if not res:
                return None
            pid = res[0][0]
            c.execute("SELECT pname from Projects where pid=?", (pid,))
            res = c.fetchall()
            if not res:
                return None
        connection.commit()
    return res[0][0]


def get_pname_bname(bname):
    with closing(sqlite3.connect(BLINTDB_LOCATION)) as connection:
        with closing(connection.cursor()) as c:
            c.execute("SELECT pid from Binaries where bname=?", (bname,))
            res = c.fetchall()
            if not res:
                return None
            pid = res[0][0]
            c.execute("SELECT pname from Projects where pid=?", (pid,))
            res = c.fetchall()
            if not res:
                return None
        connection.commit()
    return res[0][0]
