#!/usr/bin/env python3

import argparse
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB = Path("/opt/dxlaprs-manager/data/monitor.db")
RETENTION_DAYS = 30
BATCH_SIZE = 1000
MAX_SECONDS = 60


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(days=RETENTION_DAYS)
    ).isoformat()

    print("===== DXLAPRS DATABASE MAINTENANCE =====", flush=True)
    print(f"Database: {DB}", flush=True)
    print(f"Retention: {RETENTION_DAYS} giorni", flush=True)
    print(f"Cutoff UTC: {cutoff}", flush=True)
    print(f"Modalità: {'ESECUZIONE' if args.execute else 'SIMULAZIONE'}", flush=True)

    if not DB.is_file():
        raise SystemExit("ERRORE: database non trovato")

    if args.execute:
        con = sqlite3.connect(str(DB), timeout=2)
    else:
        con = sqlite3.connect(
            f"file:{DB}?mode=ro",
            uri=True,
            timeout=2
        )
        con.execute("PRAGMA query_only=ON")

    con.execute("PRAGMA busy_timeout=2000")

    try:
        for table in ("events", "packets"):
            print(f"\n===== {table.upper()} =====", flush=True)

            start = time.monotonic()
            total = 0

            while True:
                elapsed = time.monotonic() - start

                if elapsed >= MAX_SECONDS:
                    print("Limite di tempo raggiunto.", flush=True)
                    break

                ids = con.execute(
                    f"""
                    SELECT id
                    FROM {table}
                    WHERE timestamp < ?
                    ORDER BY timestamp
                    LIMIT ?
                    """,
                    (cutoff, BATCH_SIZE)
                ).fetchall()

                if not ids:
                    print("Nessun altro record da eliminare.", flush=True)
                    break

                if not args.execute:
                    print(
                        f"Simulazione: trovati {len(ids)} record nel primo blocco.",
                        flush=True
                    )
                    break

                t0 = time.monotonic()

                try:
                    con.execute("BEGIN IMMEDIATE")

                    con.executemany(
                        f"DELETE FROM {table} WHERE id = ?",
                        ids
                    )

                    con.commit()

                except BaseException:
                    con.rollback()
                    raise

                total += len(ids)

                print(
                    f"Eliminati {total} record da {table} "
                    f"(ultimo blocco: {time.monotonic() - t0:.2f}s)",
                    flush=True
                )

                time.sleep(0.05)

            if args.execute:
                print(
                    f"Totale eliminato da {table}: {total}",
                    flush=True
                )

        print("\nManutenzione terminata.", flush=True)

    finally:
        con.close()


if __name__ == "__main__":
    main()
