#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import sys
import logging
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, Optional, List, Set, Tuple

import geoip2.database
import geoip2.errors
import requests


# =========================
# Columns / Schema
# =========================

NEW_COLS_PT = [
    "cidade",
    "estado",
    "país",
    "país ISO",
    "accuracy_radius_km",
    "latitude",
    "longitude",
]

FIELDS_EN = [
    "city",
    "state",
    "country",
    "country_iso",
    "accuracy_radius_km",
    "latitude",
    "longitude",
]

EN_TO_PT = {
    "city": "cidade",
    "state": "estado",
    "country": "país",
    "country_iso": "país ISO",
    "accuracy_radius_km": "accuracy_radius_km",
    "latitude": "latitude",
    "longitude": "longitude",
}


# =========================
# Logging
# =========================

def setup_logging(level: str, log_file: Optional[Path]) -> logging.Logger:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("geo_enrich")
    logger.setLevel(lvl)
    logger.propagate = False
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(lvl)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(lvl)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# =========================
# Helpers
# =========================

def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def detect_delimiter(sample_text: str) -> str:
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(sample_text, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return ";"


def extract_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    token = s.split()[0]
    ip_part = token.split("/", 1)[0].strip()

    try:
        ipaddress.ip_address(ip_part)
        return ip_part
    except ValueError:
        return None


def is_all_fields_present(data: Dict[str, str]) -> bool:
    return all(str(data.get(k, "")).strip() for k in FIELDS_EN)


def name_en_only(names: dict | None) -> str:
    if not names:
        return ""
    if names.get("en"):
        return str(names["en"])
    for v in names.values():
        if v:
            return str(v)
    return ""


def en_to_pt(data_en: Dict[str, str]) -> Dict[str, str]:
    return {EN_TO_PT[k]: str(data_en.get(k, "") or "") for k in FIELDS_EN}


def safe_csv_writer(f_out, fieldnames: List[str], delimiter: str) -> csv.DictWriter:
    return csv.DictWriter(
        f_out,
        fieldnames=fieldnames,
        delimiter=delimiter,
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL,
        doublequote=True,
        lineterminator="\n",
        extrasaction="ignore",
    )


def apply_drop_ip_to_fieldnames(fieldnames: List[str], ip_col: str, drop_ip_col: bool) -> List[str]:
    if drop_ip_col and ip_col in fieldnames:
        return [c for c in fieldnames if c != ip_col]
    return fieldnames


def maybe_drop_ip_from_row(row: Dict[str, Any], ip_col: str, drop_ip_col: bool) -> None:
    if drop_ip_col:
        row.pop(ip_col, None)


# =========================
# Local MMDB lookup (EN only)
# =========================

def lookup_mmdb(reader: geoip2.database.Reader, ip_str: str) -> Dict[str, str]:
    try:
        resp = reader.city(ip_str)
    except geoip2.errors.AddressNotFoundError:
        return {k: "" for k in FIELDS_EN}

    city = name_en_only(getattr(resp.city, "names", None))
    country = name_en_only(getattr(resp.country, "names", None))

    subdiv = resp.subdivisions.most_specific if resp.subdivisions else None
    state = name_en_only(getattr(subdiv, "names", None)) if subdiv else ""

    loc = resp.location
    accuracy = getattr(loc, "accuracy_radius", None)
    lat = getattr(loc, "latitude", None)
    lon = getattr(loc, "longitude", None)

    return {
        "city": city,
        "state": state,
        "country": country,
        "country_iso": getattr(resp.country, "iso_code", None) or "",
        "accuracy_radius_km": "" if accuracy is None else str(accuracy),
        "latitude": "" if lat is None else str(lat),
        "longitude": "" if lon is None else str(lon),
    }


# =========================
# API fallback: ipgeolocation.io (EN only)
# =========================

class IPGeoAPIError(RuntimeError):
    def __init__(self, status_code: int, message: str, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def lookup_ipgeolocation(ip_str: str, api_key: str, timeout_sec: int) -> Dict[str, str]:
    url = "https://api.ipgeolocation.io/v3/ipgeo"
    params = {"apiKey": api_key, "ip": ip_str, "lang": "en"}

    r = requests.get(url, params=params, timeout=timeout_sec)

    if not r.ok:
        body = (r.text or "")[:800]
        # Best-effort parse a friendlier message
        msg = ""
        try:
            obj = r.json()
            if isinstance(obj, dict) and obj.get("message"):
                msg = str(obj["message"])
        except Exception:
            pass

        if not msg:
            msg = f"HTTP {r.status_code}"

        raise IPGeoAPIError(status_code=r.status_code, message=msg, body=body)

    obj = r.json()
    loc = obj.get("location", {}) if isinstance(obj, dict) else {}

    return {
        "city": str(loc.get("city", "") or ""),
        "state": str(loc.get("state_prov", "") or ""),
        "country": str(loc.get("country_name", "") or ""),
        "country_iso": str(loc.get("country_code2", "") or ""),
        "accuracy_radius_km": "",  # not present in free v3 payload
        "latitude": str(loc.get("latitude", "") or ""),
        "longitude": str(loc.get("longitude", "") or ""),
    }


# =========================
# Persistence: cache, daily usage, event log
# =========================

def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def usage_file_for_today(cache_dir: Path) -> Path:
    return cache_dir / f"ipgeo_usage_{date.today().isoformat()}.json"


def get_daily_usage(cache_dir: Path) -> int:
    data = load_json(usage_file_for_today(cache_dir), default={"count": 0})
    try:
        return int(data.get("count", 0))
    except Exception:
        return 0


def inc_daily_usage(cache_dir: Path) -> int:
    p = usage_file_for_today(cache_dir)
    data = load_json(p, default={"count": 0})
    count = int(data.get("count", 0)) + 1
    save_json(p, {"count": count, "date": date.today().isoformat()})
    return count


def cache_path_for_ip(cache_dir: Path, ip_str: str) -> Path:
    safe = ip_str.replace(":", "_")
    return cache_dir / "ip_cache" / f"{safe}.json"


def load_ip_cache(cache_dir: Path, ip_str: str) -> Optional[Dict[str, str]]:
    p = cache_path_for_ip(cache_dir, ip_str)
    if not p.exists():
        return None
    obj = load_json(p, default=None)
    if not isinstance(obj, dict):
        return None
    data = obj.get("data")
    if isinstance(data, dict):
        return {k: str(data.get(k, "") or "") for k in FIELDS_EN}
    return None


def save_ip_cache(cache_dir: Path, ip_str: str, data: Dict[str, str], source: str) -> None:
    p = cache_path_for_ip(cache_dir, ip_str)
    payload = {
        "ip": ip_str,
        "source": source,
        "saved_at": now_iso(),
        "data": {k: str(data.get(k, "") or "") for k in FIELDS_EN},
    }
    save_json(p, payload)


# =========================
# Core enrichment (MMDB -> API only if MMDB incomplete)
# =========================

def enrich_ip(
    ip_str: str,
    mmdb_reader: geoip2.database.Reader,
    api_key: Optional[str],
    cache_dir: Path,
    event_log: Path,
    daily_limit: int,
    timeout_sec: int,
    logger: logging.Logger,
) -> Dict[str, Any]:
    cached = load_ip_cache(cache_dir, ip_str)
    if cached and is_all_fields_present(cached):
        logger.debug(f"[{ip_str}] cache hit (complete)")
        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "cache", "status": "ok", "data": cached})
        return {"data_en": cached, "source": "cache", "error": "", "api_used": False}

    mmdb_data = lookup_mmdb(mmdb_reader, ip_str)
    if is_all_fields_present(mmdb_data):
        logger.debug(f"[{ip_str}] mmdb hit (complete)")
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb")
        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "mmdb", "status": "ok", "data": mmdb_data})
        return {"data_en": mmdb_data, "source": "mmdb", "error": "", "api_used": False}

    append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "mmdb", "status": "partial", "data": mmdb_data})
    logger.info(f"[{ip_str}] mmdb incomplete -> eligible for API fallback")

    if not api_key:
        msg = "No API key for fallback."
        logger.warning(f"[{ip_str}] {msg}")
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb_partial")
        return {"data_en": mmdb_data, "source": "mmdb_partial", "error": msg, "api_used": False}

    used = get_daily_usage(cache_dir)
    if used >= daily_limit:
        err = f"Daily API limit reached ({daily_limit}/day). Current usage: {used}."
        logger.error(f"[{ip_str}] {err}")
        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "ipgeolocation", "status": "error", "error": err})
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb_partial_limit")
        return {"data_en": mmdb_data, "source": "limit_hit", "error": err, "api_used": False}

    # Call API, but DO NOT print traceback; log a clean message.
    try:
        logger.info(f"[{ip_str}] calling API ipgeolocation (used today: {used}/{daily_limit})")
        api_data = lookup_ipgeolocation(ip_str, api_key=api_key, timeout_sec=timeout_sec)

        # Count only on success (200)
        new_count = inc_daily_usage(cache_dir)
        logger.info(f"[{ip_str}] API success (count today: {new_count}/{daily_limit})")

        merged = dict(mmdb_data)
        for k in FIELDS_EN:
            v = str(api_data.get(k, "") or "").strip()
            if v:
                merged[k] = v

        status = "ok" if is_all_fields_present(merged) else "partial"
        source = "ipgeolocation" if status == "ok" else "ipgeolocation_partial"
        save_ip_cache(cache_dir, ip_str, merged, source=source)

        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "ipgeolocation", "status": status, "api_count_today": new_count, "data": merged})
        logger.info(f"[{ip_str}] API result: {status}")
        return {"data_en": merged, "source": source, "error": "", "api_used": True}

    except IPGeoAPIError as e:
        # No traceback here; just a clean log entry
        if e.status_code == 401:
            err = f"ipgeolocation API unauthorized (401): {e}"
        elif e.status_code == 429:
            err = f"ipgeolocation API rate/limit (429): {e}"
        else:
            err = f"ipgeolocation API error ({e.status_code}): {e}"

        logger.error(f"[{ip_str}] {err}")
        # keep a short body for diagnostics (no traceback)
        if e.body:
            logger.debug(f"[{ip_str}] ipgeolocation body: {e.body}")

        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "ipgeolocation", "status": "error", "error": err, "http_status": e.status_code})
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb_partial_api_error")
        return {"data_en": mmdb_data, "source": "api_error", "error": err, "api_used": True}

    except (requests.Timeout, requests.ConnectionError) as e:
        err = f"ipgeolocation request failed: {type(e).__name__}: {e}"
        logger.warning(f"[{ip_str}] {err}")
        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "ipgeolocation", "status": "error", "error": err})
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb_partial_api_error")
        return {"data_en": mmdb_data, "source": "api_error", "error": err, "api_used": True}

    except Exception as e:
        # Clean log (no traceback)
        err = f"ipgeolocation unexpected error: {type(e).__name__}: {e}"
        logger.error(f"[{ip_str}] {err}")
        append_jsonl(event_log, {"ts": now_iso(), "ip": ip_str, "source": "ipgeolocation", "status": "error", "error": err})
        save_ip_cache(cache_dir, ip_str, mmdb_data, source="mmdb_partial_api_error")
        return {"data_en": mmdb_data, "source": "api_error", "error": err, "api_used": True}


# =========================
# Mode: enrich all rows from input CSV
# =========================

def run_csv_enrich_all(
    mmdb_path: Path,
    input_csv: Path,
    output_csv: Path,
    ip_col: str,
    encoding: str,
    api_key: Optional[str],
    cache_dir: Path,
    event_log: Path,
    daily_limit: int,
    timeout_sec: int,
    missing_csv: Optional[Path],
    progress_every: int,
    drop_ip_col: bool,
    logger: logging.Logger,
) -> int:
    sample = input_csv.read_text(encoding=encoding, errors="replace")[:8192]
    delimiter = detect_delimiter(sample)

    logger.info("Mode=enrich_all")
    logger.info(f"mmdb={mmdb_path} input={input_csv} output={output_csv} ip_col={ip_col}")
    logger.info(f"encoding={encoding} delimiter={delimiter!r} cache_dir={cache_dir} event_log={event_log}")
    logger.info(f"daily_limit={daily_limit} timeout={timeout_sec}s api_key={'set' if api_key else 'NOT set'} progress_every={progress_every}")
    logger.info(f"drop_ip_col={drop_ip_col}")

    missing_rows: List[dict] = []
    total = 0
    invalid_ip = 0

    with geoip2.database.Reader(str(mmdb_path)) as reader, \
         input_csv.open("r", encoding=encoding, newline="") as f_in, \
         output_csv.open("w", encoding=encoding, newline="") as f_out:

        csv_reader = csv.DictReader(f_in, delimiter=delimiter)
        if not csv_reader.fieldnames:
            logger.error("CSV without header")
            return 2
        if ip_col not in csv_reader.fieldnames:
            logger.error(f'Column "{ip_col}" not found. Columns={csv_reader.fieldnames}')
            return 2

        out_fieldnames = list(csv_reader.fieldnames)
        out_fieldnames = apply_drop_ip_to_fieldnames(out_fieldnames, ip_col, drop_ip_col)

        for c in NEW_COLS_PT:
            if c not in out_fieldnames:
                out_fieldnames.append(c)
        if "__geo_source" not in out_fieldnames:
            out_fieldnames.append("__geo_source")
        if "__geo_error" not in out_fieldnames:
            out_fieldnames.append("__geo_error")

        writer = safe_csv_writer(f_out, out_fieldnames, delimiter=delimiter)
        writer.writeheader()

        for idx, row in enumerate(csv_reader, start=2):
            total += 1
            ip_str = extract_ip(row.get(ip_col, ""))

            if not ip_str:
                invalid_ip += 1
                for c in NEW_COLS_PT:
                    row[c] = ""
                row["__geo_source"] = "invalid_ip"
                row["__geo_error"] = "Invalid/empty IP"
                missing_rows.append({"line": idx, "ip": str(row.get(ip_col, "")), "reason": "invalid_ip", "source": "invalid_ip", "error": "Invalid/empty IP"})
                maybe_drop_ip_from_row(row, ip_col, drop_ip_col)
                writer.writerow(row)
                continue

            result = enrich_ip(
                ip_str=ip_str,
                mmdb_reader=reader,
                api_key=api_key,
                cache_dir=cache_dir,
                event_log=event_log,
                daily_limit=daily_limit,
                timeout_sec=timeout_sec,
                logger=logger,
            )

            row.update(en_to_pt(result["data_en"]))
            row["__geo_source"] = result["source"]
            row["__geo_error"] = result["error"] or ""

            still_missing = any(not str(row.get(c, "")).strip() for c in NEW_COLS_PT)
            if still_missing:
                missing_rows.append({"line": idx, "ip": ip_str, "reason": "missing_fields", "source": result["source"], "error": (result["error"] or "")[:500]})

            maybe_drop_ip_from_row(row, ip_col, drop_ip_col)
            writer.writerow(row)

            if progress_every > 0 and total % progress_every == 0:
                logger.info(f"Progress: {total} rows | invalid_ip={invalid_ip} missing={len(missing_rows)} api_used_today={get_daily_usage(cache_dir)}")

    logger.info(f"Finished enrich_all. rows={total} invalid_ip={invalid_ip} missing={len(missing_rows)}")

    if missing_csv:
        missing_csv.parent.mkdir(parents=True, exist_ok=True)
        with missing_csv.open("w", encoding=encoding, newline="") as f_m:
            w = safe_csv_writer(f_m, ["line", "ip", "reason", "source", "error"], delimiter=";")
            w.writeheader()
            for r in missing_rows:
                w.writerow({
                    "line": r.get("line", ""),
                    "ip": r.get("ip", ""),
                    "reason": r.get("reason", ""),
                    "source": r.get("source", ""),
                    "error": r.get("error", ""),
                })
        logger.info(f"Missing CSV saved: {missing_csv}")

    print(f"OK: generated {output_csv}")
    if missing_rows:
        print(f"Missing enrichment rows: {len(missing_rows)}")
        if missing_csv:
            print(f"Missing CSV saved to: {missing_csv}")
    else:
        print("No records missing enrichment.")
    return 0


# =========================
# Mode: resume missing rows (update an already enriched CSV)
# =========================

def read_missing_lines(missing_csv: Path, encoding: str, logger: logging.Logger) -> Set[int]:
    sample = missing_csv.read_text(encoding=encoding, errors="replace")[:8192]
    delimiter = detect_delimiter(sample)

    lines: Set[int] = set()
    with missing_csv.open("r", encoding=encoding, newline="") as f:
        r = csv.DictReader(f, delimiter=delimiter)
        if not r.fieldnames or "line" not in r.fieldnames:
            raise ValueError(f'faltantes.csv must have a "line" column. Found: {r.fieldnames}')

        for row in r:
            v = str(row.get("line", "")).strip()
            if not v:
                continue
            try:
                lines.add(int(v))
            except ValueError:
                continue

    logger.info(f"Resume: loaded {len(lines)} lines from missing file {missing_csv}")
    return lines


def run_resume_missing(
    mmdb_path: Path,
    enriched_csv_in: Path,
    missing_csv_in: Path,
    enriched_csv_out: Path,
    missing_csv_out: Path,
    ip_col: str,
    encoding: str,
    api_key: Optional[str],
    cache_dir: Path,
    event_log: Path,
    daily_limit: int,
    timeout_sec: int,
    progress_every: int,
    drop_ip_col: bool,
    logger: logging.Logger,
) -> int:
    logger.info("Mode=resume_missing")
    logger.info(f"mmdb={mmdb_path}")
    logger.info(f"enriched_in={enriched_csv_in}")
    logger.info(f"missing_in={missing_csv_in}")
    logger.info(f"enriched_out={enriched_csv_out}")
    logger.info(f"missing_out={missing_csv_out}")
    logger.info(f"ip_col={ip_col} daily_limit={daily_limit} timeout={timeout_sec}s api_key={'set' if api_key else 'NOT set'} progress_every={progress_every}")
    logger.info(f"drop_ip_col={drop_ip_col}")

    retry_lines = read_missing_lines(missing_csv_in, encoding=encoding, logger=logger)

    sample = enriched_csv_in.read_text(encoding=encoding, errors="replace")[:8192]
    delimiter = detect_delimiter(sample)

    new_missing_rows: List[dict] = []
    processed = 0
    skipped = 0
    invalid_ip = 0
    limit_hits = 0

    with geoip2.database.Reader(str(mmdb_path)) as reader, \
         enriched_csv_in.open("r", encoding=encoding, newline="") as f_in, \
         enriched_csv_out.open("w", encoding=encoding, newline="") as f_out:

        csv_reader = csv.DictReader(f_in, delimiter=delimiter)
        if not csv_reader.fieldnames:
            logger.error("Enriched CSV without header")
            return 2
        if ip_col not in csv_reader.fieldnames:
            logger.error(f'Column "{ip_col}" not found in enriched CSV. Columns={csv_reader.fieldnames}')
            return 2

        out_fieldnames = list(csv_reader.fieldnames)
        out_fieldnames = apply_drop_ip_to_fieldnames(out_fieldnames, ip_col, drop_ip_col)

        for c in NEW_COLS_PT:
            if c not in out_fieldnames:
                out_fieldnames.append(c)
        if "__geo_source" not in out_fieldnames:
            out_fieldnames.append("__geo_source")
        if "__geo_error" not in out_fieldnames:
            out_fieldnames.append("__geo_error")

        writer = safe_csv_writer(f_out, out_fieldnames, delimiter=delimiter)
        writer.writeheader()

        for idx, row in enumerate(csv_reader, start=2):
            if idx not in retry_lines:
                skipped += 1
                maybe_drop_ip_from_row(row, ip_col, drop_ip_col)
                writer.writerow(row)
                continue

            processed += 1
            ip_str = extract_ip(row.get(ip_col, ""))

            if not ip_str:
                invalid_ip += 1
                row["__geo_source"] = "invalid_ip"
                row["__geo_error"] = "Invalid/empty IP"
                new_missing_rows.append({"line": idx, "ip": str(row.get(ip_col, "")), "reason": "invalid_ip", "source": "invalid_ip", "error": "Invalid/empty IP"})
                maybe_drop_ip_from_row(row, ip_col, drop_ip_col)
                writer.writerow(row)
                continue

            result = enrich_ip(
                ip_str=ip_str,
                mmdb_reader=reader,
                api_key=api_key,
                cache_dir=cache_dir,
                event_log=event_log,
                daily_limit=daily_limit,
                timeout_sec=timeout_sec,
                logger=logger,
            )

            row.update(en_to_pt(result["data_en"]))
            row["__geo_source"] = result["source"]
            row["__geo_error"] = result["error"] or ""

            if result["source"] == "limit_hit":
                limit_hits += 1

            still_missing = any(not str(row.get(c, "")).strip() for c in NEW_COLS_PT)
            if still_missing:
                new_missing_rows.append({
                    "line": idx,
                    "ip": ip_str,
                    "reason": "missing_fields",
                    "source": result["source"],
                    "error": (result["error"] or "")[:500],
                })

            maybe_drop_ip_from_row(row, ip_col, drop_ip_col)
            writer.writerow(row)

            if progress_every > 0 and processed % progress_every == 0:
                logger.info(
                    f"Resume progress: retried={processed}/{len(retry_lines)} | new_missing={len(new_missing_rows)} "
                    f"| limit_hits={limit_hits} api_used_today={get_daily_usage(cache_dir)}"
                )

    missing_csv_out.parent.mkdir(parents=True, exist_ok=True)
    with missing_csv_out.open("w", encoding=encoding, newline="") as f_m:
        w = safe_csv_writer(f_m, ["line", "ip", "reason", "source", "error"], delimiter=";")
        w.writeheader()
        for r in new_missing_rows:
            w.writerow({
                "line": r.get("line", ""),
                "ip": r.get("ip", ""),
                "reason": r.get("reason", ""),
                "source": r.get("source", ""),
                "error": r.get("error", ""),
            })

    logger.info(f"Resume finished. retried={processed} skipped={skipped} invalid_ip={invalid_ip} new_missing={len(new_missing_rows)} limit_hits={limit_hits}")
    logger.info(f"Updated CSV saved: {enriched_csv_out}")
    logger.info(f"New missing CSV saved: {missing_csv_out}")

    print(f"OK: updated CSV written to {enriched_csv_out}")
    print(f"Retried missing lines: {processed} (from {len(retry_lines)} in {missing_csv_in})")
    print(f"New missing rows: {len(new_missing_rows)} -> {missing_csv_out}")
    if limit_hits:
        print(f"API daily limit prevented completion for some rows (limit_hit occurrences): {limit_hits}")

    return 0


# =========================
# Mode: single IP lookup
# =========================

def run_ip_lookup(
    mmdb_path: Path,
    ip_value: str,
    api_key: Optional[str],
    cache_dir: Path,
    event_log: Path,
    daily_limit: int,
    timeout_sec: int,
    pretty: bool,
    logger: logging.Logger,
) -> int:
    ip_str = extract_ip(ip_value)
    if not ip_str:
        logger.error(f"Invalid IP: {ip_value!r}")
        print(f"Erro: invalid IP: {ip_value!r}", file=sys.stderr)
        return 2

    with geoip2.database.Reader(str(mmdb_path)) as reader:
        result = enrich_ip(
            ip_str=ip_str,
            mmdb_reader=reader,
            api_key=api_key,
            cache_dir=cache_dir,
            event_log=event_log,
            daily_limit=daily_limit,
            timeout_sec=timeout_sec,
            logger=logger,
        )

    out = {"ip": ip_str, "source": result["source"], "error": result["error"], **result["data_en"]}
    print(json.dumps(out, ensure_ascii=False, indent=2 if pretty else None))
    return 0


# =========================
# CLI
# =========================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Enrich IPs with GeoLite2 MMDB (EN) and fallback ipgeolocation.io (EN). Includes resume mode for missing lines."
    )
    p.add_argument("--mmdb", required=True, help="Path to GeoLite2-City.mmdb")

    # Common
    p.add_argument("--ip-col", default="Endereço IP", help='IP column name (default: "Endereço IP")')
    p.add_argument("--encoding", default="utf-8-sig", help="CSV encoding (default: utf-8-sig)")
    p.add_argument("--drop-ip-col", action="store_true", help='Remove IP column from output CSV (keeps using it to enrich).')

    # API fallback
    p.add_argument("--ipgeo-key", default=os.getenv("IPGEOLOCATION_API_KEY", ""), help="ipgeolocation.io API key (or env IPGEOLOCATION_API_KEY)")
    p.add_argument("--daily-limit", type=int, default=1000, help="Daily API limit (default: 1000)")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds (default: 15)")

    # Persistence
    p.add_argument("--cache-dir", default=".geo_cache", help="Cache dir (default: .geo_cache)")
    p.add_argument("--event-log", default="geo_enrichment_events.jsonl", help="Event log JSONL (default: geo_enrichment_events.jsonl)")

    # Logging
    p.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR (default: INFO)")
    p.add_argument("--log-file", default="", help="Optional log file path (e.g. ./run.log)")
    p.add_argument("--progress-every", type=int, default=5000, help="Progress log every N rows (default: 5000)")

    # Modes
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ip", help="Single IP lookup")
    mode.add_argument("--enrich-all", action="store_true", help="Enrich all rows from an input CSV")
    mode.add_argument("--resume-missing", action="store_true", help="Resume: enrich only rows listed in missing CSV and update enriched CSV")

    # Enrich-all args
    p.add_argument("--input", help="Input CSV (enrich-all mode)")
    p.add_argument("--output", help="Output CSV (enrich-all mode)")
    p.add_argument("--missing-csv", default="", help="Missing CSV output path (enrich-all mode)")

    # Resume-missing args
    p.add_argument("--enriched-in", help="Already enriched CSV input (resume-missing mode)")
    p.add_argument("--missing-in", help="Missing CSV input with 'line' column (resume-missing mode)")
    p.add_argument("--enriched-out", help="Updated enriched CSV output (resume-missing mode)")
    p.add_argument("--missing-out", help="New missing CSV output (resume-missing mode)")

    args = p.parse_args()

    mmdb_path = Path(args.mmdb)
    if not mmdb_path.exists():
        print(f"Error: MMDB not found: {mmdb_path}", file=sys.stderr)
        return 2

    cache_dir = Path(args.cache_dir)
    event_log = Path(args.event_log)
    api_key = args.ipgeo_key.strip() or None
    log_file = Path(args.log_file) if args.log_file.strip() else None
    logger = setup_logging(args.log_level, log_file)

    logger.info("Starting geo enrichment script")
    logger.info(f"Python={sys.version.split()[0]} PID={os.getpid()}")
    logger.info(f"cache_dir={cache_dir} event_log={event_log} daily_limit={args.daily_limit}")

    if args.ip:
        return run_ip_lookup(
            mmdb_path=mmdb_path,
            ip_value=args.ip,
            api_key=api_key,
            cache_dir=cache_dir,
            event_log=event_log,
            daily_limit=args.daily_limit,
            timeout_sec=args.timeout,
            pretty=True,
            logger=logger,
        )

    if args.enrich_all:
        if not args.input or not args.output:
            print("Error: --input and --output are required for --enrich-all", file=sys.stderr)
            return 2

        input_csv = Path(args.input)
        output_csv = Path(args.output)
        if not input_csv.exists():
            print(f"Error: input CSV not found: {input_csv}", file=sys.stderr)
            return 2

        missing_csv = Path(args.missing_csv) if args.missing_csv.strip() else None

        return run_csv_enrich_all(
            mmdb_path=mmdb_path,
            input_csv=input_csv,
            output_csv=output_csv,
            ip_col=args.ip_col,
            encoding=args.encoding,
            api_key=api_key,
            cache_dir=cache_dir,
            event_log=event_log,
            daily_limit=args.daily_limit,
            timeout_sec=args.timeout,
            missing_csv=missing_csv,
            progress_every=args.progress_every,
            drop_ip_col=args.drop_ip_col,
            logger=logger,
        )

    if args.resume_missing:
        if not args.enriched_in or not args.missing_in or not args.enriched_out or not args.missing_out:
            print("Error: --enriched-in --missing-in --enriched-out --missing-out are required for --resume-missing", file=sys.stderr)
            return 2

        enriched_in = Path(args.enriched_in)
        missing_in = Path(args.missing_in)
        enriched_out = Path(args.enriched_out)
        missing_out = Path(args.missing_out)

        if not enriched_in.exists():
            print(f"Error: enriched-in CSV not found: {enriched_in}", file=sys.stderr)
            return 2
        if not missing_in.exists():
            print(f"Error: missing-in CSV not found: {missing_in}", file=sys.stderr)
            return 2

        resume_progress = max(1, (args.progress_every // 10)) if args.progress_every else 1000

        return run_resume_missing(
            mmdb_path=mmdb_path,
            enriched_csv_in=enriched_in,
            missing_csv_in=missing_in,
            enriched_csv_out=enriched_out,
            missing_csv_out=missing_out,
            ip_col=args.ip_col,
            encoding=args.encoding,
            api_key=api_key,
            cache_dir=cache_dir,
            event_log=event_log,
            daily_limit=args.daily_limit,
            timeout_sec=args.timeout,
            progress_every=resume_progress,
            drop_ip_col=args.drop_ip_col,
            logger=logger,
        )

    return 2


if __name__ == "__main__":
    raise SystemExit(main())