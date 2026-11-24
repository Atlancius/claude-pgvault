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
import shutil
import re
import stat
import subprocess
import sys

VERSION = "0.3.1"
CONF_VARS = ("PGVAULT_PSQL", "PGVAULT_KEY_FILE", "PGVAULT_KEY_CMD", "PGVAULT_SCHEMA", "PGVAULT_TABLE",
             "PGVAULT_PGP_OPTIONS")
# Mêmes options que le coffre de référence : AES-256, compression zlib avant chiffrement.
DEFAULT_PGP_OPTIONS = "cipher-algo=aes256,compress-algo=1"
PGP_OPT = re.compile(r"^[a-z0-9-]+=[a-z0-9-]+(,[a-z0-9-]+=[a-z0-9-]+)*$")
IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
KEYNAME = re.compile(r"^[A-Za-z0-9_.:/@-]{1,200}$")


class VaultError(Exception):
    pass


def shell(cmd, **kw):
    """Lance une ligne de commande dans un shell POSIX (sh), même sous Windows (Git Bash)."""
    # Octets en entrée et en sortie : sous Windows, le mode texte ajouterait des retours chariot.
    for k in ("text", "encoding", "errors"):
        kw.pop(k, None)
    if isinstance(kw.get("input"), str):
        kw["input"] = kw["input"].encode("utf-8")
    sh = shutil.which("sh")
    argv, use_shell = ([sh, "-c", cmd], False) if sh else (cmd, True)
    p = subprocess.run(argv, shell=use_shell, **kw)
    dec = lambda b: b.decode("utf-8", errors="replace").replace("\r\n", "\n") if isinstance(b, bytes) else b
    p.stdout, p.stderr = dec(p.stdout), dec(p.stderr)
    return p


# ---------------------------------------------------------------- configuration

def conf_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.environ.get("PGVAULT_CONFIG") or os.path.join(base, "pgvault", "config.env")


def read_conf():
    """Fichier KEY=VALUE (aucun secret dedans : chemins et commandes seulement)."""
    out = {}
    try:
        with open(conf_path(), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if len(v) >= 2 and v[0] == v[-1] == "'":
                    v = v[1:-1].replace("'\\''", "'")
                if k in CONF_VARS:
                    out[k] = v
    except OSError:
        pass
    return out


def setting(name, default=""):
    """Variable d'environnement d'abord, puis fichier de configuration."""
    v = os.environ.get(name)
    if v is None:
        v = read_conf().get(name)
    return default if v is None else v


def cfg():
    schema = setting("PGVAULT_SCHEMA", "vault")
    table = setting("PGVAULT_TABLE", "secrets")
    opts = setting("PGVAULT_PGP_OPTIONS", DEFAULT_PGP_OPTIONS).strip()
    if not PGP_OPT.match(opts):
        raise VaultError("PGVAULT_PGP_OPTIONS invalide (ex. cipher-algo=aes256,compress-algo=1)")
    for name, v in (("PGVAULT_SCHEMA", schema), ("PGVAULT_TABLE", table)):
        if not IDENT.match(v):
            raise VaultError(f"{name} invalide : lettres minuscules, chiffres et _ seulement")
    return {
        "psql": setting("PGVAULT_PSQL", "psql").strip() or "psql",
        "key_file": setting("PGVAULT_KEY_FILE").strip(),
        "key_cmd": setting("PGVAULT_KEY_CMD").strip(),
        "pgp": opts,
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
        p = shell(c["key_cmd"], capture_output=True, text=True)
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
    p = shell(cmd, input=head + sql, capture_output=True, text=True, encoding="utf-8")
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


def store(c, key, value, description=None, expires_at=None, source="pgvault"):
    """Chiffre et range une valeur. Ne renvoie que sa longueur."""
    key = check_keyname(key)
    if not value:
        raise VaultError("valeur vide : rien n'est écrit")
    if expires_at:
        try:
            _dt.date.fromisoformat(expires_at[:10])
        except ValueError:
            raise VaultError("--expires-at attend une date AAAA-MM-JJ") from None
    mk = load_key(c)
    cols = columns(c)
    if not cols:
        raise VaultError(f"table {c['fq']} absente : lancer `pgvault init`")
    names, vals = ["key", "value_encrypted"], [lit(key), f"pgp_sym_encrypt({lit(value)}, {lit(mk)}, '{c['pgp']}')"]
    if "description" in cols and description is not None:
        names.append("description"); vals.append(lit(description))
    if "expires_at" in cols and expires_at:
        names.append("expires_at"); vals.append(lit(expires_at) + "::timestamptz")
    if "source" in cols:
        names.append("source"); vals.append(lit(source))
    for n, meta in cols.items():  # horodatages obligatoires sans défaut (schémas existants)
        if n in names or n == "expires_at" or not meta["type"].startswith("timestamp"):
            continue
        if n == "updated_at" or (not meta["nullable"] and not meta["default"]):
            names.append(n); vals.append("now()")
    upd = ", ".join(f"{n} = EXCLUDED.{n}" for n in names if n != "key")
    psql(c, f"INSERT INTO {c['fq']} ({', '.join(names)}) VALUES ({', '.join(vals)}) "
            f"ON CONFLICT (key) DO UPDATE SET {upd};\n")
    return len(value)


def exists(c, key):
    return bool(psql(c, f"SELECT 1 FROM {c['fq']} WHERE key = {lit(check_keyname(key))};\n"))


# Vérification en ligne, avant écriture (comme le coffre d'origine : « rien n'est écrit » si refusé).
VERIFIERS = [
    ("github", re.compile(r"^(gh[pousr]_|github_pat_)"), "https://api.github.com/user",
     lambda v: {"Authorization": f"Bearer {v}", "User-Agent": "pgvault"}),
    ("anthropic", re.compile(r"^sk-ant-"), "https://api.anthropic.com/v1/models",
     lambda v: {"x-api-key": v, "anthropic-version": "2023-06-01"}),
    ("openai", re.compile(r"^sk-(?!ant-)"), "https://api.openai.com/v1/models",
     lambda v: {"Authorization": f"Bearer {v}"}),
    ("stripe", re.compile(r"^(sk|rk)_(live|test)_"), "https://api.stripe.com/v1/balance",
     lambda v: {"Authorization": f"Bearer {v}"}),
]


def verify(value):
    """(fournisseur, None) si accepté ; lève VaultError si refusé ; (None, None) si format inconnu."""
    import urllib.error
    import urllib.request
    for name, rx, url, headers in VERIFIERS:
        if rx.match(value):
            req = urllib.request.Request(url, headers=headers(value))
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    if 200 <= r.status < 300:
                        return name
            except urllib.error.HTTPError as e:
                raise VaultError(f"{name} refuse ce secret (HTTP {e.code}) : rien n'est écrit") from None
            except OSError:
                raise VaultError(f"{name} injoignable : rien n'est écrit (relancer sans --verify ?)") from None
            raise VaultError(f"réponse inattendue de {name} : rien n'est écrit")
    return None


def cmd_put(c, a):
    key = check_keyname(a.key)
    if sys.stdin.isatty():
        value = getpass.getpass(f"valeur de {key} (saisie masquée) : ")
    else:
        value = sys.stdin.read()
        if value.endswith("\r\n"):
            value = value[:-2]
        elif value.endswith("\n"):
            value = value[:-1]
    if not value:
        raise VaultError("valeur vide : rien n'est écrit")
    checked = ""
    if a.verify:
        who = verify(value)
        checked = f", vérifié auprès de {who}" if who else ", format inconnu : non vérifié"
    n = store(c, key, value, a.description, a.expires_at)
    print(f"ok {key} ({n} caractères{checked})")


# ---------------------------------------------------------------- capture des secrets collés dans un prompt

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("stripe_test_key", re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}")),
    ("stripe_webhook_secret", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
# « token: xxx », « api_key = xxx », « mot de passe : xxx » : la valeur après le signe.
ASSIGN = re.compile(r"(?i)\b([a-z][a-z0-9_ .-]{0,30}?(?:token|secret|password|passwd|api[_ -]?key|apikey|"
                    r"mot de passe|clé|cle|key))\s*[:=]\s*[\"']?([^\s\"']{12,})")
CANDIDATE = re.compile(r"(?<![A-Za-z0-9_/+=.-])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9_/+=.-])")


def entropy(s):
    import math
    from collections import Counter
    n = len(s)
    return -sum(k / n * math.log2(k / n) for k in Counter(s).values()) if n else 0.0


def looks_random(s):
    """Peu de faux positifs : long, varié, pas de l'hexadécimal pur (empreintes git), pas un chemin."""
    if len(s) < 32 or re.fullmatch(r"[0-9a-fA-F-]+", s) or s.count("/") > 2:
        return False
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return classes == 3 and entropy(s) >= 4.3


def find_secrets(text):
    """[(type, valeur, nom suggéré)] sans doublon, dans l'ordre d'apparition."""
    found, spans = [], []

    def add(kind, value, start, end, hint=""):
        if any(start < e and end > s for s, e in spans):
            return
        spans.append((start, end))
        found.append((start, kind, value, hint))

    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            add(kind, m.group(0), m.start(), m.end())
    for m in ASSIGN.finditer(text):
        v = m.group(2)
        if (len(v) >= 16 and entropy(v) >= 3.5 and not v.startswith(("http", "$", "<", "{"))) or looks_random(v):
            add("secret", v, m.start(2), m.end(2), m.group(1))
    for m in CANDIDATE.finditer(text):
        if looks_random(m.group(0)):
            add("secret", m.group(0), m.start(), m.end())
    found.sort()
    return [(k, v, h) for _, k, v, h in found]


def suggest_name(kind, hint):
    if kind == "secret" and hint:
        base = re.sub(r"[^a-z0-9]+", "_", hint.lower()).strip("_") or "secret"
        if not base.endswith(("token", "secret", "key", "password")):
            base += "_secret"
        return base[:60]
    return kind


def free_name(c, base, taken):
    name, i = base, 2
    while name in taken or exists(c, name):
        name, i = f"{base}_{i}", i + 1
    taken.add(name)
    return name


def cmd_scan(c, a):
    """Test de détection : lit un texte, affiche types et noms proposés, jamais les valeurs."""
    hits = find_secrets(sys.stdin.read())
    for kind, value, hint in hits:
        print(f"{kind}\t{suggest_name(kind, hint)}\t{len(value)} caractères")
    return 0 if hits else 1


def cmd_capture(c, a):
    """Hook UserPromptSubmit : range au coffre tout secret du prompt, puis bloque le prompt."""
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    prompt = data.get("prompt") or ""
    if not isinstance(prompt, str):
        return 0
    hits = find_secrets(prompt)
    if not hits:
        return 0
    today = _dt.date.today().isoformat()
    saved, failed = [], ""
    try:
        cc = cfg()
        taken = set()
        for kind, value, hint in hits:
            name = free_name(cc, suggest_name(kind, hint), taken)
            store(cc, name, value, f"{kind} capturé depuis un prompt le {today}", source="pgvault-capture")
            saved.append((name, kind))
    except VaultError as e:
        failed = str(e)
    lines = ["pgvault : ton message contenait un secret. Il n'a PAS été envoyé au modèle."]
    if saved:
        lines.append("Rangé au coffre (chiffré) :")
        lines += [f"  - {n} ({k})" for n, k in saved]
        lines.append("Renvoie ta demande en citant ce nom au lieu de la valeur, par exemple : "
                     f"« utilise le secret {saved[0][0]} du coffre ».")
    if failed:
        lines.append(f"Non rangé : {failed}. Lance /pgvault:setup, ou range-le dans ton terminal avec "
                     "`pgvault put <nom>` (saisie masquée), puis renvoie ta demande sans la valeur.")
    spawn_scrub(data.get("transcript_path") or "", [(v, n) for (n, _), (_, v, _) in zip(saved, hits)]
                + [(v, k) for k, v, _ in hits[len(saved):]])
    print(json.dumps({"decision": "block", "reason": "\n".join(lines)}, ensure_ascii=False))
    return 0


def spawn_scrub(transcript, pairs):
    """Claude Code écrit le prompt bloqué dans la transcription locale APRÈS le hook. Un processus détaché
    remplace ensuite chaque valeur par [pgvault:<nom>] (transcription et historique des prompts).
    Les valeurs passent par l'entrée standard du processus, jamais en argument."""
    if not transcript or not pairs:
        return
    try:
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kw["start_new_session"] = True
        child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "scrub", "--transcript", transcript],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        child.stdin.write(json.dumps([[v, n] for v, n in pairs]).encode("utf-8"))
        child.stdin.close()
    except OSError:
        pass


def _scrub_file(path, pairs):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return 0
    n = 0
    for value, name in pairs:
        for form in {value, json.dumps(value)[1:-1]}:
            if form and form in text:
                n += text.count(form)
                text = text.replace(form, f"[pgvault:{name}]")
    if n:
        tmp = path + ".pgvault.tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
    return n


def cmd_scrub(c, a):
    import time
    try:
        pairs = [tuple(x) for x in json.load(sys.stdin)]
    except (ValueError, OSError):
        return 1
    paths = [a.transcript]
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(a.transcript))))
    paths.append(os.path.join(base, "history.jsonl"))
    total = 0
    for delay in (1, 3, 8, 20, 60):  # la transcription s'écrit après le hook, parfois en plusieurs fois
        time.sleep(delay)
        total += sum(_scrub_file(p_, pairs) for p_ in paths)
    return 0


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


# ---------------------------------------------------------------- détection et configuration

PG_IMAGES = re.compile(r"postgres|postgis|timescale|supabase|pgvector|paradedb", re.I)
URL_PASS = re.compile(r"(://[^:/@\s]+):[^@\s]+@")


def mask(v):
    return URL_PASS.sub(r"\1:***@", v)


def _sh(cmd, timeout=20):
    try:
        p = shell(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "délai dépassé"


def _q(s):
    """Guillemets simples POSIX."""
    return "'" + s.replace("'", "'\\''") + "'"


# Tables qui ont les deux colonnes d'un coffre pgcrypto (noms seulement, jamais de contenu).
PROBE_SQL = ("SELECT table_schema || '.' || table_name FROM information_schema.columns "
             "WHERE column_name IN ('key','value_encrypted') "
             "AND table_schema NOT IN ('pg_catalog','information_schema') GROUP BY 1 HAVING count(*) = 2 ORDER BY 1")

PROBE_SH = r'''U="${POSTGRES_USER:-postgres}"
for d in $(psql -U "$U" -d "${POSTGRES_DB:-$U}" -Atc "select datname from pg_database where not datistemplate and datallowconn" 2>/dev/null | head -20); do
  echo "db $d"
  psql -U "$U" -d "$d" -At 2>/dev/null <<'SQL' | sed "s/^/vault $d /"
''' + PROBE_SQL + r''';
SQL
done'''


def _probe_container(prefix, name):
    """Bases et tables de coffre d'un conteneur Postgres (noms seulement)."""
    if prefix:
        cmd = f"{prefix}{_q('docker exec -i ' + _q(name) + ' sh -s')}"
    else:
        cmd = f"docker exec -i {_q(name)} sh -s"
    try:
        p = shell(cmd, input=PROBE_SH, capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=40)
        out = p.stdout
    except subprocess.TimeoutExpired:
        out = ""
    dbs, vaults = [], []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "db":
            dbs.append(parts[1])
        elif len(parts) == 3 and parts[0] == "vault":
            vaults.append({"db": parts[1], "table": parts[2]})
    return dbs, vaults


KEY_GLOBS = ("~/.config/pgvault/*.key /etc/*/vault.key /etc/*/*vault*.key "
             "/root/.config/pgvault/*.key /opt/*/vault.key")


def _key_files(prefix):
    script = (f"for f in {KEY_GLOBS}; do [ -f \"$f\" ] && ls -ld \"$f\"; done 2>/dev/null")
    cmd = prefix + _q("sh -c " + _q(script)) if prefix else "sh -c " + _q(script)
    _, out, _ = _sh(cmd, timeout=20)
    res, seen = [], set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[-1] in seen:
            continue
        seen.add(parts[-1])
        res.append({"path": parts[-1], "perms": parts[0], "private": parts[0][4:10] == "------"})
    return res


def _ssh_hosts():
    hosts = []
    try:
        with open(os.path.join(os.path.expanduser("~"), ".ssh", "config"), encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^\s*Host\s+(.+)$", line, re.I)
                if m:
                    hosts += [h for h in m.group(1).split() if not any(ch in h for ch in "*?!")]
    except OSError:
        pass
    return hosts


def detect(ssh_host=""):
    if ssh_host and not re.match(r"^[A-Za-z0-9_.@-]+$", ssh_host):
        raise VaultError("nom d'hôte SSH invalide")
    prefix = f"ssh -o BatchMode=yes -o ConnectTimeout=10 {ssh_host} " if ssh_host else ""
    r = {"where": f"ssh {ssh_host}" if ssh_host else "local", "psql": False, "local_server": False,
         "docker": False, "containers": [], "key_files": [], "ssh_hosts": [], "env": {}}
    run = (lambda s: _sh(prefix + _q(s))) if ssh_host else (lambda s: _sh(s))
    if ssh_host:
        rc, _, err = _sh(prefix + "true", timeout=20)
        if rc != 0:
            r["error"] = "connexion SSH impossible : " + _clean(err)
            return r
    r["psql"] = run("command -v psql >/dev/null 2>&1")[0] == 0
    r["local_server"] = run("pg_isready -q -h localhost >/dev/null 2>&1")[0] == 0
    rc, out, _ = run("docker ps --format '{{.Names}}|{{.Image}}'")
    if rc == 0:
        r["docker"] = True
        for line in out.splitlines():
            if "|" not in line:
                continue
            name, image = line.split("|", 1)
            if PG_IMAGES.search(image):
                dbs, vaults = _probe_container(prefix, name)
                r["containers"].append({"name": name, "image": image, "databases": dbs, "vault_tables": vaults})
    r["key_files"] = _key_files(prefix)
    if not ssh_host:
        r["ssh_hosts"] = _ssh_hosts()
        for v in CONF_VARS + ("DATABASE_URL",):
            if os.environ.get(v):
                r["env"][v] = "défini"
        r["config_file"] = conf_path() if os.path.exists(conf_path()) else ""
    return r


def suggestions(r, ssh_host=""):
    pre = f"ssh {ssh_host} " if ssh_host else ""
    out = []
    for c in r["containers"]:
        inner = lambda db: f"docker exec -i {c['name']} sh -lc 'psql -U \"$POSTGRES_USER\" -d {db}'"
        for v in c["vault_tables"]:
            sch, tab = v["table"].split(".", 1)
            psql_cmd = (pre + _q(inner(v["db"]))) if pre else inner(v["db"])
            out.append({"label": f"coffre existant {v['table']} (conteneur {c['name']}, base {v['db']})",
                        "PGVAULT_PSQL": psql_cmd, "PGVAULT_SCHEMA": sch, "PGVAULT_TABLE": tab})
        if not c["vault_tables"]:
            db = c["databases"][0] if c["databases"] else "postgres"
            psql_cmd = (pre + _q(inner(db))) if pre else inner(db)
            out.append({"label": f"nouveau coffre dans le conteneur {c['name']} (base {db})",
                        "PGVAULT_PSQL": psql_cmd})
    if r["local_server"] and r["psql"]:
        out.append({"label": "serveur PostgreSQL local" + (f" de {ssh_host}" if ssh_host else ""),
                    "PGVAULT_PSQL": (pre + _q("psql -h localhost -d postgres")) if pre else "psql -h localhost -d postgres"})
    if r["env"].get("DATABASE_URL"):
        out.append({"label": "base de DATABASE_URL", "PGVAULT_PSQL": 'psql "$DATABASE_URL"'})
    for k in r["key_files"]:
        k["suggest"] = ({"PGVAULT_KEY_CMD": f"ssh {ssh_host} cat {k['path']}"} if ssh_host
                        else {"PGVAULT_KEY_FILE": k["path"]})
    return out


def cmd_detect(c, a):
    r = detect(a.ssh)
    r["suggestions"] = suggestions(r, a.ssh) if "error" not in r else []
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if "error" not in r else 1
    if "error" in r:
        print(r["error"])
        return 1
    y = lambda b: "oui" if b else "non"
    print(f"Lieu : {r['where']}")
    print(f"  psql : {y(r['psql'])} | PostgreSQL local : {y(r['local_server'])} | Docker : {y(r['docker'])}")
    for ct in r["containers"]:
        vt = ", ".join(f"{v['db']}:{v['table']}" for v in ct["vault_tables"]) or "aucun coffre"
        print(f"  conteneur {ct['name']} ({ct['image']}) : bases {', '.join(ct['databases']) or '?'} ; {vt}")
    for k in r["key_files"]:
        print(f"  clé trouvée : {k['path']} ({k['perms']}{'' if k['private'] else ', TROP OUVERTE : chmod 600'})")
    if r.get("ssh_hosts"):
        print(f"  hôtes SSH connus : {', '.join(r['ssh_hosts'])}")
    for k in r.get("env", {}):
        print(f"  variable {k} : définie")
    if r.get("config_file"):
        print(f"  configuration : {r['config_file']}")
    print("Suggestions :" if r["suggestions"] else "Aucune base PostgreSQL détectée ici.")
    for i, s_ in enumerate(r["suggestions"], 1):
        print(f"  {i}. {s_['label']}\n     PGVAULT_PSQL={s_['PGVAULT_PSQL']}")
        if "PGVAULT_TABLE" in s_:
            print(f"     PGVAULT_SCHEMA={s_['PGVAULT_SCHEMA']}  PGVAULT_TABLE={s_['PGVAULT_TABLE']}")
    for k in r["key_files"]:
        (n, v), = k["suggest"].items()
        print(f"  clé : {n}={v}")
    return 0


def cmd_config(c, a):
    path = conf_path()
    if a.action == "path":
        print(path)
        return 0
    cur = read_conf()
    if a.action == "show":
        for k in CONF_VARS:
            src = "env" if os.environ.get(k) is not None else ("fichier" if k in cur else "défaut")
            val = os.environ.get(k, cur.get(k, ""))
            print(f"{k}={mask(val)}\t({src})")
        return 0
    if a.name not in CONF_VARS:
        raise VaultError("variable inconnue ; autorisées : " + ", ".join(CONF_VARS))
    if a.action == "set":
        if a.value is None or "\n" in a.value:
            raise VaultError("usage : pgvault config set NOM \"VALEUR sur une ligne\"")
        cur[a.name] = a.value
    else:
        cur.pop(a.name, None)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write("# pgvault : configuration (aucun secret ici). Les variables d'environnement priment.\n")
        for k in CONF_VARS:
            if k in cur:
                f.write(f"{k}={_q(cur[k])}\n")
    os.replace(tmp, path)
    print(f"ok : {a.name} {'enregistré' if a.action == 'set' else 'retiré'} ({path})")
    return 0


# ---------------------------------------------------------------- garde-fou agent

GUARD = [
    (re.compile(r"pgvault(\.py)?[\"']?\s+reveal\b"), "pgvault reveal affiche une valeur : utilise `pgvault run`"),
    (re.compile(r"PGVAULT_ALLOW_REVEAL"), "PGVAULT_ALLOW_REVEAL est réservé à l'humain"),
    (re.compile(r"pgp_sym_decrypt", re.I), "déchiffrement SQL direct interdit : utilise `pgvault run`"),
]
# `pgvault config set PGVAULT_KEY_CMD "..."` cite légitimement la clé ; une seule commande, sans chaînage.
CONFIG_CMD = re.compile(r"^\s*[\w./\\:\"'${}-]*pgvault(\.py|\.cmd)?[\"']?\s+(config|detect)\b[^;&|`\n]*$")
READERS = re.compile(r"\b(cat|type|less|more|head|tail|bat|nl|od|xxd|base64|strings|cp|scp|Get-Content|gc|sed|awk|grep|python3?|node)\b")


def guard_decision(command, key_file=""):
    for rx, why in GUARD:
        if rx.search(command):
            return why
    if CONFIG_CMD.match(command):
        return None
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
    p.add_argument("--verify", action="store_true", help="vérifie le secret auprès du fournisseur avant d'écrire")
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
    p = sub.add_parser("detect", help="détecte psql, PostgreSQL local, conteneurs, coffres et clés (local ou --ssh hôte)")
    p.add_argument("--ssh", default="", metavar="HOTE")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("config", help="configuration persistante : show, set, unset, path")
    p.add_argument("action", choices=["show", "set", "unset", "path"])
    p.add_argument("name", nargs="?")
    p.add_argument("value", nargs="?")
    sub.add_parser("guard", help="hook PreToolUse pour agents")
    sub.add_parser("capture", help="hook UserPromptSubmit : range les secrets d'un prompt et le bloque")
    sub.add_parser("scan", help="détecte les secrets d'un texte (stdin), sans afficher les valeurs")
    p = sub.add_parser("scrub", help=argparse.SUPPRESS)
    p.add_argument("--transcript", required=True)
    a = ap.parse_args(argv)
    try:
        c = cfg() if a.cmd not in ("guard", "detect", "config", "capture", "scan", "scrub") else {}
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
