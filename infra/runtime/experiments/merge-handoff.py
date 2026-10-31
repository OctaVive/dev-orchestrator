#!/usr/bin/env python3
"""Consolidate immutable records from two actual M07 lab stores.
Only operator-owned, private, trusted metadata databases are inputs; no workload
archive is opened. Admission/job/deployment/event IDs and payloads are preserved. Local outbox
surrogate sequence numbers may be reassigned when consolidating stores.
"""
import argparse
import os
from pathlib import Path
import sqlite3
import stat


def checked(path):
    path=Path(path).resolve(strict=True)
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_size>16<<20:
        raise RuntimeError('private trusted lab metadata required')
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True)
    parser.add_argument('--source',required=True)
    args=parser.parse_args()
    target,source=checked(args.target),checked(args.source)
    if target==source:raise RuntimeError('distinct snapshots required')
    connection=sqlite3.connect(target)
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('ATTACH DATABASE ? AS prior',(str(source),))
    tables=[row[0] for row in connection.execute("SELECT name FROM prior.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_migrations'")]
    connection.execute('BEGIN IMMEDIATE')
    try:
        connection.execute('PRAGMA defer_foreign_keys=ON')
        for name in tables:
            # Names come from the trusted migration-owned schema, never a request.
            if not name.replace('_','').isalnum():raise RuntimeError('unexpected schema name')
            fields=list(connection.execute(f'PRAGMA prior.table_info("{name}")'))
            local_sequence=name in ('outbox','clone_outbox','build_outbox') and any(row[1]=='id' and row[2].upper()=='INTEGER' and row[5]==1 for row in fields)
            columns=','.join('"'+row[1]+'"' for row in fields if not(local_sequence and row[1]=='id'))
            connection.execute(f'INSERT OR IGNORE INTO main."{name}" ({columns}) SELECT {columns} FROM prior."{name}"')
            missing=connection.execute(f'SELECT {columns} FROM prior."{name}" EXCEPT SELECT {columns} FROM main."{name}" LIMIT 1').fetchone()
            if missing is not None:raise RuntimeError('conflicting immutable metadata in '+name)
        if connection.execute('PRAGMA main.foreign_key_check').fetchone() is not None:
            raise RuntimeError('incomplete metadata graph')
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    print('M09-HANDOFF-RECORDS-CONSOLIDATED')


if __name__=='__main__':main()
