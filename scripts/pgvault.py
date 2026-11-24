#!/usr/bin/env python3
"""pgvault : coffre de secrets dans PostgreSQL, chiffré par pgcrypto (pgp_sym_encrypt, AES-256).

Aucune commande n'affiche une valeur, sauf `reveal`, réservée à un humain (PGVAULT_ALLOW_REVEAL=1).
Les secrets passent aux programmes par `pgvault run --env VAR=cle -- commande`.

Configuration (variables d'environnement) :
  PGVAULT_PSQL      commande qui lance psql et lit le SQL sur l'entrée standard
                    (défaut : psql ; ex. psql "$DATABASE_URL", docker exec -i pg psql -U app -d app,
                    ssh mon-serveur docker exec -i pg psql -U app -d app)
  PGVAULT_KEY_FILE  fichier qui contient la clé maître (droits 600)
  PGVAULT_KEY_CMD   à défaut, commande dont la sortie est la clé maître
  PGVAULT_SCHEMA    schéma du coffre (défaut : vault)
  PGVAULT_TABLE     table du coffre (défaut : secrets)

Python 3.8+, bibliothèque standard seulement. Licence MIT.
"""
import argparse
import datetime as _dt
import getpass
import json
import os
import re
import stat
import subprocess
import sys

VERSION = "0.1.0"
IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
KEYNAME = re.compile(r"^[A-Za-z0-9_.:/@-]{1,200}$")


class VaultError(Exception):
    pass


# ---------------------------------------------------------------- configuration

def cfg():
    schema = os.environ.get("PGVAULT_SCHEMA", "vault")
    table = os.environ.get("PGVAULT_TABLE", "secrets")
    for name, v in (("PGVAULT_SCHEMA", schema), ("PGVAULT_TABLE", table)):
        if not IDENT.match(v):
            raise VaultError(f"{name} invalide : lettres minuscules, chiffres et _ seulement")
    return {
        "psql": os.environ.get("PGVAULT_PSQL", "psql").strip() or "psql",
        "key_file": os.environ.get("PGVAULT_KEY_FILE", "").strip(),
        "key_cmd": os.environ.get("PGVAULT_KEY_CMD", "").strip(),
        "fq": f"{schema}.{table}",
        "schema": schema,
        "table": table,
    }


def load_key(c):
    if c["key_file"]:
        path = os.path.expanduser(c["key_file"])
        try:
            with open(path, encoding="utf-8") as f:
                key = f.read().strip()
        except OSError as e:
            raise VaultError(f"clé illisible ({e.strerror})") from None
    elif c["key_cmd"]:
        p = subprocess.run(c["key_cmd"], shell=True, capture_output=True, text=True)
        if p.returncode != 0:
            raise VaultError("PGVAULT_KEY_CMD a échoué (détail masqué)")
        key = p.stdout.strip()
    else:
        raise VaultError("aucune clé : définir PGVAULT_KEY_FILE ou PGVAULT_KEY_CMD")
    if len(key) < 16:
        raise VaultError("clé trop courte (16 caractères minimum)")
    return key


def lit(s):
    """Littéral SQL sûr : la chaîne voyage en hexadécimal, sans guillemet à échapper."""
    return "convert_from(decode('" + s.encode("utf-8").hex() + "','hex'),'UTF8')"


_HEX = re.compile(r"[0-9a-fA-F]{16,}")


def _clean(err):
    """Erreur psql sans contexte SQL : la clé ou une valeur ne peut pas fuiter."""
    lines = [l for l in err.splitlines() if not re.match(r"^\s*(LINE \d+:|\^|CONTEXT:|QUERY:|STATEMENT:)", l)]
    return _HEX.sub("[masqué]", " ".join(l.strip() for l in lines if l.strip()))[:300]


def psql(c, sql):
    # Options en tête du SQL aussi : elles s'appliquent même quand psql est enveloppé (sh -c, ssh, docker exec).
    cmd = c["psql"] + " -X -q -At -v ON_ERROR_STOP=1"
    head = ("\\set QUIET on\n\\set ON_ERROR_STOP on\n\\pset format unaligned\n"
            "\\pset tuples_only on\n\\pset footer off\n")
    p = subprocess.run(cmd, shell=True, input=head + sql, capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        raise VaultError("psql : " + (_clean(p.stderr) or f"code {p.returncode}"))
    return [l for l in p.stdout.splitlines() if l != ""]


def columns(c):
    rows = psql(c, (
        "SELECT column_name, data_type, is_nullable, coalesce(column_default,'') FROM information_schema.columns "
        f"WHERE table_schema = {lit(c['schema'])} AND table_name = {lit(c['table'])};\n"))
    out = {}
    for r in rows:
        name, typ, nullable, default = r.split("|", 3)
        out[name] = {"type": typ, "nullable": nullable == "YES", "default": default}
    return out


def check_keyname(k):
    if not KEYNAME.match(k):
        raise VaultError("nom de clé invalide (lettres, chiffres, _ . : / @ -, 200 max)")
    return k


def read(c, keys):
    keys = [check_keyname(k) for k in keys]
    if not keys:
        return {}
    mk = load_key(c)
    sql = ("SELECT encode(convert_to(key,'UTF8'),'hex'), encode(convert_to(pgp_sym_decrypt(value_encrypted, "
           + lit(mk) + "),'UTF8'),'hex') FROM " + c["fq"] + " WHERE key IN (" + ",".join(lit(k) for k in keys) + ");\n")
    out = {}
    for line in psql(c, sql):
        k, v = line.split("|", 1)
        out[bytes.fromhex(k).decode()] = bytes.fromhex(v).decode()
    return out


# ---------------------------------------------------------------- commandes

def cmd_init(c, a):
    psql(c, (
        "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
        f"CREATE SCHEMA IF NOT EXISTS {c['schema']};\n"
        f"CREATE TABLE IF NOT EXISTS {c['fq']} (\n"
        "  key text PRIMARY KEY,\n"
        "  value_encrypted bytea NOT NULL,\n"
        "  description text NOT NULL DEFAULT '',\n"
        "  expires_at timestamptz,\n"
        "  source text NOT NULL DEFAULT '',\n"
        "  updated_at timestamptz NOT NULL DEFAULT now()\n"
        ");\n"
        f"REVOKE ALL ON {c['fq']} FROM PUBLIC;\n"))
    print(f"ok : coffre {c['fq']} prêt (pgcrypto actif)")


def cmd_doctor(c, a):
    ok = True

    def line(state, msg):
        nonlocal ok
        ok = ok and state != "FAIL"
        print(f"[{state}] {msg}")

    line("OK", f"pgvault {VERSION}, Python {sys.version.split()[0]}")
    if c["key_file"]:
        path = os.path.expanduser(c["key_file"])
        if not os.path.exists(path):
            line("FAIL", "PGVAULT_KEY_FILE : fichier introuvable")
        else:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if os.name == "posix" and mode & 0o077:
                line("WARN", f"PGVAULT_KEY_FILE lisible par d'autres (droits {oct(mode)}) : chmod 600")
            else:
                line("OK", "PGVAULT_KEY_FILE présent")
    elif c["key_cmd"]:
        line("OK", "PGVAULT_KEY_CMD défini")
    else:
        line("FAIL", "aucune clé : PGVAULT_KEY_FILE ou PGVAULT_KEY_CMD")
    try:
        key = load_key(c)
        line("OK", f"clé chargée ({len(key)} caractères)")
    except VaultError as e:
        line("FAIL", str(e))
    try:
        v = psql(c, "SELECT current_setting('server_version');\n")
        line("OK", f"psql joignable (PostgreSQL {v[0] if v else '?'})")
    except VaultError as e:
        line("FAIL", str(e))
        print("verdict : FAIL")
        return 1
    ext = psql(c, "SELECT extversion FROM pg_extension WHERE extname = 'pgcrypto';\n")
    line("OK" if ext else "FAIL", f"pgcrypto {ext[0]}" if ext else "pgcrypto absent : lancer `pgvault init`")
    cols = columns(c)
    if not cols:
        line("FAIL", f"table {c['fq']} absente : lancer `pgvault init`")
    else:
        missing = {"key", "value_encrypted"} - set(cols)
        if missing:
            line("FAIL", f"colonnes manquantes : {', '.join(sorted(missing))}")
        else:
            n = psql(c, f"SELECT count(*) FROM {c['fq']};\n")
            line("OK", f"table {c['fq']} : {n[0]} secrets")
            if ok:
                try:
                    probe = psql(c, f"SELECT key FROM {c['fq']} ORDER BY key LIMIT 1;\n")
                    if probe:
                        read(c, [probe[0]])
                        line("OK", "déchiffrement vérifié sur un secret (valeur non affichée)")
                except VaultError:
                    line("FAIL", "déchiffrement impossible : mauvaise clé maître ?")
    print("verdict : " + ("OK" if ok else "FAIL"))
    return 0 if ok else 1


def cmd_list(c, a):
    cols = columns(c)
    exp = "coalesce(to_char(expires_at,'YYYY-MM-DD'),'')" if "expires_at" in cols else "''"
    desc = "coalesce(description,'')" if "description" in cols else "''"
    where = f" WHERE key LIKE {lit(a.prefix)} || '%'" if a.prefix else ""
    rows = psql(c, f"SELECT key, {exp}, replace({desc}, E'\\n', ' ') FROM {c['fq']}{where} ORDER BY key;\n")
    if a.json:
        print(json.dumps([dict(zip(("key", "expires_at", "description"), r.split("|", 2))) for r in rows],
                         ensure_ascii=False, indent=2))
        return
    for r in rows:
        k, e, d = r.split("|", 2)
        print(f"{k}\t{e or '-'}\t{d}")
    print(f"{len(rows)} secret(s)", file=sys.stderr)


def cmd_put(c, a):
    key = check_keyname(a.key)
    if sys.stdin.isatty():
        value = getpass.getpass(f"valeur de {key} (masquée) : ")
    else:
        value = sys.stdin.read()
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
    if not value:
        raise VaultError("valeur vide : rien n'est écrit")
    if a.expires_at:
        try:
            _dt.date.fromisoformat(a.expires_at[:10])
        except ValueError:
            raise VaultError("--expires-at attend une date AAAA-MM-JJ") from None
    mk = load_key(c)
    cols = columns(c)
    if not cols:
        raise VaultError(f"table {c['fq']} absente : lancer `pgvault init`")
    names, vals = ["key", "value_encrypted"], [lit(key), f"pgp_sym_encrypt({lit(value)}, {lit(mk)}, 'cipher-algo=aes256')"]
    if "description" in cols and a.description is not None:
        names.append("description"); vals.append(lit(a.description))
    if "expires_at" in cols and a.expires_at:
        names.append("expires_at"); vals.append(lit(a.expires_at) + "::timestamptz")
    if "source" in cols:
        names.append("source"); vals.append(lit("pgvault"))
    for n, meta in cols.items():  # horodatages obligatoires sans défaut (schémas existants)
        if n not in names and n != "expires_at" and meta["type"].startswith("timestamp")                 and not meta["nullable"] and not meta["default"]:
            names.append(n); vals.append("now()")
        elif n not in names and n == "updated_at":
            names.append(n); vals.append("now()")
    upd = ", ".join(f"{n} = EXCLUDED.{n}" for n in names if n != "key")
    psql(c, f"INSERT INTO {c['fq']} ({', '.join(names)}) VALUES ({', '.join(vals)}) "
            f"ON CONFLICT (key) DO UPDATE SET {upd};\n")
    print(f"ok {key} ({len(value)} caractères)")


def cmd_has(c, a):
    got = read(c, [a.key])
    if a.key in got:
        print(f"présent : {a.key} ({len(got[a.key])} caractères)")
        return 0
    print(f"absent : {a.key}")
    return 1


def cmd_expiring(c, a):
    if "expires_at" not in columns(c):
        raise VaultError("la table n'a pas de colonne expires_at")
    rows = psql(c, f"SELECT key, to_char(expires_at,'YYYY-MM-DD') FROM {c['fq']} WHERE expires_at IS NOT NULL "
                   f"AND expires_at < now() + interval '{int(a.days)} days' ORDER BY expires_at;\n")
    for r in rows:
        k, e = r.split("|", 1)
        print(f"{k}\t{e}")
    print(f"{len(rows)} secret(s) expirent sous {a.days} jours", file=sys.stderr)
    return 1 if rows else 0


def cmd_rm(c, a):
    key = check_keyname(a.key)
    if not a.yes:
        raise VaultError("suppression définitive : relancer avec --yes")
    n = psql(c, f"WITH d AS (DELETE FROM {c['fq']} WHERE key = {lit(key)} RETURNING 1) SELECT count(*) FROM d;\n")
    print(f"supprimé : {key}" if n and n[0] != "0" else f"absent : {key}")


def cmd_run(c, a):
    cmd = list(a.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise VaultError("commande manquante : pgvault run --env VAR=cle -- commande")
    pairs = []
    for spec in a.env:
        if "=" not in spec:
            raise VaultError(f"--env attend VAR=cle : {spec!r}")
        var, key = spec.split("=", 1)
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var):
            raise VaultError(f"nom de variable invalide : {var!r}")
        pairs.append((var, key))
    got = read(c, [k for _, k in pairs])
    missing = [k for _, k in pairs if k not in got]
    if missing:
        raise VaultError("absent du coffre : " + ", ".join(missing))
    env = dict(os.environ)
    env.pop("PGVAULT_ALLOW_REVEAL", None)
    for var, key in pairs:
        env[var] = got[key]
    try:
        return subprocess.call(cmd, env=env)
    except FileNotFoundError:
        raise VaultError(f"commande introuvable : {cmd[0]}") from None


def cmd_reveal(c, a):
    if os.environ.get("PGVAULT_ALLOW_REVEAL") != "1":
        raise VaultError("reveal est réservé à un humain : PGVAULT_ALLOW_REVEAL=1 dans ton propre terminal")
    got = read(c, [a.key])
    if a.key not in got:
        raise VaultError(f"absent : {a.key}")
    sys.stdout.write(got[a.key] + ("\n" if sys.stdout.isatty() else ""))


# ---------------------------------------------------------------- garde-fou agent

GUARD = [
    (re.compile(r"pgvault(\.py)?[\"']?\s+reveal\b"), "pgvault reveal affiche une valeur : utilise `pgvault run`"),
    (re.compile(r"PGVAULT_ALLOW_REVEAL"), "PGVAULT_ALLOW_REVEAL est réservé à l'humain"),
    (re.compile(r"pgp_sym_decrypt", re.I), "déchiffrement SQL direct interdit : utilise `pgvault run`"),
]
READERS = re.compile(r"\b(cat|type|less|more|head|tail|bat|nl|od|xxd|base64|strings|cp|scp|Get-Content|gc|sed|awk|grep|python3?|node)\b")


def guard_decision(command, key_file=""):
    for rx, why in GUARD:
        if rx.search(command):
            return why
    names = {"vault.key", "pgvault.key"}
    if key_file:
        names.add(os.path.basename(os.path.expanduser(key_file)))
    for n in names:
        if n and n in command and READERS.search(command):
            return f"lecture du fichier de clé ({n}) interdite à l'agent"
    return None


def cmd_guard(c, a):
    """Hook PreToolUse (Claude Code, Codex) : lit le JSON de l'outil, bloque (code 2) les fuites évidentes."""
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    ti = data.get("tool_input") or {}
    command = ti.get("command") or ti.get("cmd") or ""
    if isinstance(command, list):
        command = " ".join(map(str, command))
    why = guard_decision(str(command), os.environ.get("PGVAULT_KEY_FILE", ""))
    if why:
        print(f"pgvault : bloqué. {why}.", file=sys.stderr)
        return 2
    return 0


# ---------------------------------------------------------------- entrée

def main(argv=None):
    ap = argparse.ArgumentParser(prog="pgvault", description="Coffre de secrets PostgreSQL + pgcrypto, sans afficher les valeurs.")
    ap.add_argument("--version", action="version", version=f"pgvault {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="crée pgcrypto, le schéma et la table")
    sub.add_parser("doctor", help="vérifie configuration, connexion, clé et table")
    p = sub.add_parser("list", help="liste les noms (jamais les valeurs)")
    p.add_argument("--prefix", default="")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("put", help="écrit un secret, valeur lue sur l'entrée standard")
    p.add_argument("key")
    p.add_argument("--description", default=None)
    p.add_argument("--expires-at", default=None, help="AAAA-MM-JJ")
    p = sub.add_parser("has", help="présence et longueur d'un secret")
    p.add_argument("key")
    p = sub.add_parser("expiring", help="secrets qui expirent bientôt")
    p.add_argument("--days", type=int, default=30)
    p = sub.add_parser("rm", help="supprime un secret (définitif)")
    p.add_argument("key")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("run", help="lance une commande avec des secrets en variables d'environnement")
    p.add_argument("--env", action="append", default=[], metavar="VAR=cle")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = sub.add_parser("reveal", help="affiche une valeur (humain seulement, PGVAULT_ALLOW_REVEAL=1)")
    p.add_argument("key")
    sub.add_parser("guard", help="hook PreToolUse pour agents")
    a = ap.parse_args(argv)
    try:
        c = cfg() if a.cmd != "guard" else {}
        fn = globals()["cmd_" + a.cmd]
        rc = fn(c, a)
        return rc or 0
    except VaultError as e:
        print(f"pgvault : {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    sys.exit(main())
