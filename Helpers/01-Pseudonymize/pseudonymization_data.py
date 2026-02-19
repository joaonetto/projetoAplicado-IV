#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hmac
import hashlib
import logging
import os
import re
import sys
from pathlib import Path
from typing import Iterable

EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@([a-z0-9\-]+\.)+[a-z]{2,}\b")
DOMAIN_TOKEN_RE = re.compile(r"(?i)\b([a-z0-9\-]+\.)+[a-z]{2,63}\b")

DOMAIN_PASSTHROUGH = {
    "admin.google.com",
    "password.google.com",
}


def normalize(s: str) -> str:
    return (s or "").strip()


def hmac_hex(secret: bytes, msg: str) -> str:
    return hmac.new(secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def setup_logging(level: str, log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("pseudonymization_data")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(stream=sys.stdout)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(fmt)
    logger.addHandler(console)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(getattr(logging, level.upper(), logging.INFO))
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def detect_delimiter(path: Path, logger: logging.Logger) -> str:
    logger.debug("Detectando delimitador em: %s", path)
    with path.open("r", encoding="utf-8", newline="") as f:
        sample = f.read(4096)

    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t|")
        logger.info("Delimitador detectado automaticamente: %r", dialect.delimiter)
        return dialect.delimiter
    except Exception as e:
        first_line = sample.splitlines()[0] if sample else ""
        delim = ";" if first_line.count(";") >= first_line.count(",") else ","
        logger.info(
            "Falha ao detectar delimitador via Sniffer (%s). Usando heurística: %r",
            type(e).__name__,
            delim,
        )
        return delim


def split_email(email: str) -> tuple[str, str]:
    e = email.strip()
    if "@" not in e:
        return e, ""
    local, dom = e.split("@", 1)
    return local, dom.lower().strip(".")


def domain_alias(domain: str, secret: bytes, suffix: str = "org.br", prefix: str = "acme") -> str:
    d = domain.lower().strip(".")
    if d in DOMAIN_PASSTHROUGH:
        return d
    token = hmac_hex(secret, d)[:8]
    return f"{prefix}-{token}.{suffix}"


def user_id_alias_from_email(email: str, secret: bytes, prefix: str = "USR", width: int = 6) -> str:
    hx = hmac_hex(secret, email.lower())
    n = int(hx[:12], 16)
    mod = 10**width
    return f"{prefix}{(n % mod):0{width}d}"


def iter_csv_rows(path: Path, delimiter: str) -> Iterable[list[str]]:
    with path.open("r", encoding="utf-8", newline="") as fin:
        reader = csv.reader(fin, delimiter=delimiter)
        for row in reader:
            yield row


def build_maps_from_file(in_path: Path, delimiter: str, secret: bytes, logger: logging.Logger) -> tuple[dict[str, str], dict[str, str]]:
    emails: set[str] = set()
    domains: set[str] = set()

    logger.info("Fase 1/2: varredura para coletar e-mails e domínios a partir de: %s", in_path)

    rows = 0
    hits = 0
    for row in iter_csv_rows(in_path, delimiter):
        rows += 1
        for cell in row:
            cell = normalize(cell)
            if not cell:
                continue
            for m in EMAIL_RE.finditer(cell):
                e = m.group(0)
                hits += 1
                emails.add(e.lower())
                _, dom = split_email(e)
                if dom:
                    domains.add(dom)

        if rows % 100_000 == 0:
            logger.info("Varredura em andamento: %d linhas processadas | %d ocorrências de e-mail", rows, hits)

    logger.info(
        "Varredura concluída: %d linhas | %d ocorrências de e-mail | %d e-mails únicos | %d domínios únicos",
        rows,
        hits,
        len(emails),
        len(domains),
    )

    domain_map: dict[str, str] = {d: domain_alias(d, secret) for d in domains}
    for d in DOMAIN_PASSTHROUGH:
        domain_map[d] = d

    email_map: dict[str, str] = {}
    for e in emails:
        _, dom = split_email(e)
        uid = user_id_alias_from_email(e, secret, prefix="USR", width=6)
        if dom in DOMAIN_PASSTHROUGH:
            email_map[e] = f"{uid}@{dom}"
        else:
            pseudo_dom = domain_map.get(dom, domain_alias(dom, secret))
            email_map[e] = f"{uid}@{pseudo_dom}"

    logger.debug("Exemplo (debug) de 3 mapeamentos de e-mail: %s", list(email_map.items())[:3])
    logger.debug("Exemplo (debug) de 3 mapeamentos de domínio: %s", list(domain_map.items())[:3])

    return email_map, domain_map


def pseudonymize_cell(cell: str, email_map: dict[str, str], domain_map: dict[str, str], replace_domain_tokens: bool) -> str:
    if not cell:
        return cell

    def repl_email(m: re.Match) -> str:
        e = m.group(0).lower()
        return email_map.get(e, m.group(0))

    out = EMAIL_RE.sub(repl_email, cell)

    if not replace_domain_tokens:
        return out

    def repl_domain(m: re.Match) -> str:
        d = m.group(0).lower().strip(".")
        if d in DOMAIN_PASSTHROUGH:
            return d
        return domain_map.get(d, m.group(0))

    return DOMAIN_TOKEN_RE.sub(repl_domain, out)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Pseudonimiza e-mails (usuário + domínio) em arquivos CSV de logs, gerando mapas de usuários e domínios.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("input_csv", help="Caminho do CSV de entrada (logs).")
    p.add_argument("output_dir", nargs="?", default=None, help="Diretório de saída. Se omitido: <pasta_do_arquivo>/pseudo_out")
    p.add_argument("--secret-env", default="LOG_PSEUDO_SECRET", help="Nome da variável de ambiente que contém o segredo para HMAC.")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "ERROR"], help="Nível de log.")
    p.add_argument("--log-file", default=None, help="Arquivo de log (opcional). Ex.: ./execucao.log")
    p.add_argument("--no-domain-tokens", action="store_true", help="Não pseudonimiza domínios 'soltos' (apenas e-mails completos).")
    return p.parse_args()


def run(args: argparse.Namespace, logger: logging.Logger) -> int:
    in_path = Path(args.input_csv).expanduser().resolve()
    if not in_path.exists():
        logger.error("Arquivo de entrada não encontrado: %s", in_path)
        return 2

    out_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else (in_path.parent / "pseudo_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    secret_str = os.environ.get(args.secret_env, "")
    if not secret_str:
        logger.error("Segredo não definido. Exporte a variável de ambiente %s.", args.secret_env)
        logger.error("Ex.: export %s='uma-chave-super-secreta'", args.secret_env)
        return 2
    secret = secret_str.encode("utf-8")

    delimiter = detect_delimiter(in_path, logger)
    email_map, domain_map = build_maps_from_file(in_path, delimiter, secret, logger)

    out_logs = out_dir / "logs_pseudo.csv"
    out_users = out_dir / "map_users.csv"
    out_domains = out_dir / "map_domains.csv"

    replace_domain_tokens = not args.no_domain_tokens
    logger.info("Fase 2/2: gerando saída (replace_domain_tokens=%s) ...", replace_domain_tokens)

    rows_out = 0
    with in_path.open("r", encoding="utf-8", newline="") as fin, out_logs.open("w", encoding="utf-8", newline="") as fout:
        reader = csv.reader(fin, delimiter=delimiter)
        writer = csv.writer(fout, delimiter=delimiter, lineterminator="\n")
        for row in reader:
            rows_out += 1
            writer.writerow([pseudonymize_cell(normalize(c), email_map, domain_map, replace_domain_tokens) for c in row])
            if rows_out % 200_000 == 0:
                logger.info("Escrita em andamento: %d linhas pseudonimizadas", rows_out)

    logger.info("Logs pseudonimizados gerados: %s (%d linhas)", out_logs, rows_out)

    with out_users.open("w", encoding="utf-8", newline="") as fu:
        w = csv.writer(fu, delimiter=delimiter, lineterminator="\n")
        w.writerow(["original_email", "pseudo_email", "user_id"])
        for original_email in sorted(email_map.keys()):
            pseudo_email = email_map[original_email]
            user_id = pseudo_email.split("@", 1)[0] if "@" in pseudo_email else ""
            w.writerow([original_email, pseudo_email, user_id])
    logger.info("Mapa de usuários gerado: %s (registros=%d)", out_users, len(email_map))

    with out_domains.open("w", encoding="utf-8", newline="") as fd:
        w = csv.writer(fd, delimiter=delimiter, lineterminator="\n")
        w.writerow(["original_domain", "pseudo_domain", "passthrough"])
        for original_domain in sorted(domain_map.keys()):
            pseudo_domain = domain_map[original_domain]
            passthrough = "true" if original_domain in DOMAIN_PASSTHROUGH else "false"
            w.writerow([original_domain, pseudo_domain, passthrough])
    logger.info("Mapa de domínios gerado: %s (registros=%d)", out_domains, len(domain_map))

    logger.info("OK! Arquivos gerados em: %s", out_dir)
    logger.info("Resumo: delimiter=%r | emails_unicos=%d | dominios_unicos=%d", delimiter, len(email_map), len(domain_map))
    return 0


def main() -> int:
    args = parse_args()
    logger = setup_logging(args.log_level, args.log_file)

    logger.info("Starting pseudonymization_data")
    logger.info("Python=%s", sys.version.split()[0])

    try:
        return run(args, logger)
    except KeyboardInterrupt:
        logger.error("Interrompido pelo usuário (Ctrl+C).")
        return 130
    except Exception as e:
        if args.log_level.upper() == "DEBUG":
            logger.exception("Falha inesperada: %s", e)
        else:
            logger.error("Falha inesperada (%s): %s", type(e).__name__, e)
            logger.error("Dica: rode novamente com --log-level DEBUG para obter traceback completo.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
