import argparse
import gzip
import json
import os
import sqlite3
import sys
import glob
import shutil
import urllib.request
from datetime import datetime

NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
DEFAULT_YEARS = range(2002, datetime.utcnow().year + 1)  # 2002


def log(msg):
    print(msg, file=sys.stderr)


def download_feed(url: str, dest: str):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        return
    log(f"Downloading {url} -> {dest}")
    with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def ensure_json_dir(json_dir: str, download: bool, years):
    os.makedirs(json_dir, exist_ok=True)
    if not download:
        return
    # recent + modified
    for name in ("nvdcve-1.1-recent.json.gz", "nvdcve-1.1-modified.json.gz"):
        download_feed(f"{NVD_BASE}/{name}", os.path.join(json_dir, name))
    # yearly
    for y in years:
        name = f"nvdcve-1.1-{y}.json.gz"
        download_feed(f"{NVD_BASE}/{name}", os.path.join(json_dir, name))


def load_json(path: str):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def create_schema(cur: sqlite3.Cursor):
    cur.executescript("""
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;

    DROP TABLE IF EXISTS cves;

    CREATE TABLE cves(
      id TEXT PRIMARY KEY,
      summary TEXT,
      product TEXT,
      version_start_inc TEXT,
      version_end_exc  TEXT
    );

    CREATE INDEX idx_product ON cves(product);
    """)


def insert_item(cur: sqlite3.Cursor, cve_id, summary, product, vmin, vmax):
    cur.execute(
        "INSERT OR IGNORE INTO cves VALUES(?,?,?,?,?)",
        (cve_id, summary, product, vmin, vmax)
    )


def process_feed(cur: sqlite3.Cursor, data: dict):
    items = data.get("CVE_Items", [])
    for it in items:
        try:
            cve = it["cve"]
            cve_id = cve["CVE_data_meta"]["ID"]
            descs = cve["description"]["description_data"]
            summary = descs[0]["value"] if descs else ""

            nodes = it.get("configurations", {}).get("nodes", [])
            for node in nodes:
                for cpe in node.get("cpe_match", []):
                    uri = cpe.get("cpe23Uri", "")
                    parts = uri.split(":")
                    if len(parts) < 6:
                        continue
                    # cpe:2.3:a:vendor:product:version:
                    product = parts[4]
                    vmin = cpe.get("versionStartIncluding")
                    vmax = cpe.get("versionEndExcluding")
                    insert_item(cur, cve_id, summary, product, vmin, vmax)
        except Exception as e:
            log(f"[warn] skipping item due to error: {e}")


def build_db(db_path: str, json_dir: str):
    files = sorted(glob.glob(os.path.join(json_dir, "nvdcve-1.1-*.json*")))
    if not files:
        log("No JSON feeds found. Use --download or put files manually.")
        return 1

    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    create_schema(cur)

    count_files = len(files)
    for i, f in enumerate(files, 1):
        log(f"[{i}/{count_files}] Processing {os.path.basename(f)}")
        try:
            data = load_json(f)
            process_feed(cur, data)
        except Exception as e:
            log(f"Error processing {f}: {e}")

    con.commit()
    con.close()
    log(f"DB saved to {db_path}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Build SQLite CVE DB (nvd.sqlite3) from NVD JSON feeds"
    )
    ap.add_argument("db_path", nargs="?", default="data/nvd.sqlite3",
                    help="output sqlite path (default: data/nvd.sqlite3)")
    ap.add_argument("--json-dir", default="data/nvd_json",
                    help="directory with NVD json(.gz) files (default: data/nvd_json)")
    ap.add_argument("--download", action="store_true",
                    help="download feeds into json-dir before building")
    ap.add_argument("--from-year", type=int, default=2002,
                    help="first year to download (default 2002)")
    ap.add_argument("--to-year", type=int, default=datetime.utcnow().year,
                    help="last year to download (default current year)")
    args = ap.parse_args()

    years = range(args.from_year, args.to_year + 1)
    ensure_json_dir(args.json_dir, args.download, years)
    return build_db(args.db_path, args.json_dir)


if __name__ == "__main__":
    sys.exit(main())
