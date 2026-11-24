#!/bin/sh
# Tests de bout en bout : cluster PostgreSQL jetable (initdb), coffre neuf, coffre au schéma existant, hook.
# Usage : sh tests/run-tests.sh   (initdb, pg_ctl, psql dans le PATH ; port 55432 libre)
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W="$ROOT/.pgvault-test"
PORT=${PGVAULT_TEST_PORT:-55432}
PV="sh $ROOT/bin/pgvault"
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS $1"; }
ko()  { fail=$((fail+1)); echo "FAIL $1"; }
expect() { name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else ko "$name"; fi; }
refuse() { name=$1; shift; if "$@" >/dev/null 2>&1; then ko "$name"; else ok "$name"; fi; }

[ -d "$W" ] && pg_ctl -D "$W/data" stop -m fast >/dev/null 2>&1 || true
[ -d "$W" ] && { command -v trash >/dev/null && trash "$W" || mv "$W" "$W.old.$$"; }
mkdir -p "$W"
initdb -D "$W/data" -U pgv -A trust -E UTF8 >/dev/null
pg_ctl -D "$W/data" -o "-p $PORT -c unix_socket_directories= -c listen_addresses=localhost" -l "$W/pg.log" -w start >/dev/null
trap 'pg_ctl -D "$W/data" stop -m fast >/dev/null 2>&1 || true' EXIT
psql -h localhost -p "$PORT" -U pgv -d postgres -qc "CREATE DATABASE app" >/dev/null

export PGVAULT_PSQL="psql -h localhost -p $PORT -U pgv -d app"
printf '%s' "test-master-key-0123456789abcdef" > "$W/vault.key"; chmod 600 "$W/vault.key"
export PGVAULT_KEY_FILE="$W/vault.key"
unset PGVAULT_KEY_CMD PGVAULT_ALLOW_REVEAL PGVAULT_SCHEMA PGVAULT_TABLE 2>/dev/null || true

SECRET='s3cr3t|avec "guillemets" et é'
expect "init" $PV init
expect "doctor coffre vide" $PV doctor
expect "put par stdin" sh -c "printf '%s' '$SECRET' | $PV put demo_token --description 'jeton de test' --expires-at 2000-01-01"
out=$($PV list 2>/dev/null)
case "$out" in *demo_token*) ok "list montre le nom";; *) ko "list montre le nom";; esac
case "$out" in *s3cr3t*) ko "list ne montre pas la valeur";; *) ok "list ne montre pas la valeur";; esac
out=$($PV has demo_token)
case "$out" in *"(29 caractères)"*) ok "has donne la longueur";; *) ko "has donne la longueur ($out)";; esac
refuse "has absent -> code 1" $PV has absent_key
got=$($PV run --env T=demo_token -- python -c 'import os,sys; sys.stdout.buffer.write(os.environ["T"].encode("utf-8"))')
[ "$got" = "$SECRET" ] && ok "run injecte la valeur exacte" || ko "run injecte la valeur exacte"
refuse "run clé absente" $PV run --env T=absent -- true
refuse "expiring signale un secret expiré" $PV expiring --days 1
refuse "reveal refusé sans PGVAULT_ALLOW_REVEAL" $PV reveal demo_token
got=$(PGVAULT_ALLOW_REVEAL=1 $PV reveal demo_token)
[ "$got" = "$SECRET" ] && ok "reveal humain" || ko "reveal humain"
expect "doctor déchiffre" $PV doctor
printf '%s' "mauvaise-cle-0123456789abcdef" > "$W/bad.key"
refuse "mauvaise clé refusée" env PGVAULT_KEY_FILE="$W/bad.key" $PV has demo_token
err=$(PGVAULT_KEY_FILE="$W/bad.key" $PV has demo_token 2>&1 || true)
hex=$(printf '%s' "mauvaise-cle-0123456789abcdef" | od -An -tx1 | tr -d ' \n')
case "$err" in *"$hex"*|*mauvaise-cle*) ko "erreur sans la clé";; *) ok "erreur sans la clé";; esac
expect "put remplace" sh -c "printf 'v2' | $PV put demo_token"
got=$($PV run --env T=demo_token -- python -c 'import os,sys; sys.stdout.buffer.write(os.environ["T"].encode("utf-8"))')
[ "$got" = "v2" ] && ok "valeur remplacée" || ko "valeur remplacée"
raw=$(psql -h localhost -p "$PORT" -U pgv -d app -Atc "select encode(value_encrypted,'escape') from vault.secrets")
case "$raw" in *v2*) ko "valeur chiffrée en base";; *) ok "valeur chiffrée en base";; esac
refuse "rm sans --yes" $PV rm demo_token
expect "rm --yes" $PV rm demo_token --yes

# Coffre existant : colonnes NOT NULL sans défaut (source, horodatage), autre schéma.
psql -h localhost -p "$PORT" -U pgv -d app -q >/dev/null <<'SQL'
CREATE SCHEMA legacy;
CREATE TABLE legacy.coffre (key text PRIMARY KEY, value_encrypted bytea NOT NULL, description text NOT NULL DEFAULT '',
  expires_at timestamptz, old_updated_at timestamptz NOT NULL, source text NOT NULL, migrated_at timestamptz NOT NULL DEFAULT now());
SQL
expect "schéma existant : put" sh -c "printf 'abc' | PGVAULT_SCHEMA=legacy PGVAULT_TABLE=coffre $PV put k1"
expect "schéma existant : doctor" env PGVAULT_SCHEMA=legacy PGVAULT_TABLE=coffre $PV doctor
refuse "identifiant SQL invalide" env PGVAULT_TABLE='x;drop' $PV list

# Compatibilité croisée avec un écrivain externe (mêmes options pgcrypto, clé passée en hexadécimal).
KH=$(printf '%s' "test-master-key-0123456789abcdef" | od -An -tx1 | tr -d ' \n')
psql -h localhost -p "$PORT" -U pgv -d app -q >/dev/null <<SQL
INSERT INTO legacy.coffre (key, value_encrypted, source, old_updated_at)
VALUES ('ext', pgp_sym_encrypt('valeur-externe', convert_from(decode('$KH','hex'),'UTF8'), 'cipher-algo=aes256,compress-algo=1'), 'externe', now());
SQL
got=$(PGVAULT_SCHEMA=legacy PGVAULT_TABLE=coffre $PV run --env T=ext -- python -c 'import os,sys; sys.stdout.write(os.environ["T"])')
[ "$got" = "valeur-externe" ] && ok "lit un secret écrit par un autre outil" || ko "lit un secret écrit par un autre outil"
got=$(psql -h localhost -p "$PORT" -U pgv -d app -Atc "select pgp_sym_decrypt(value_encrypted, convert_from(decode('$KH','hex'),'UTF8')) from legacy.coffre where key='k1'")
[ "$got" = "abc" ] && ok "un autre outil lit un secret écrit par pgvault" || ko "un autre outil lit un secret écrit par pgvault"

# Configuration persistante
export PGVAULT_CONFIG="$W/config.env"
SAVED_PSQL=$PGVAULT_PSQL; unset PGVAULT_PSQL
expect "config set" $PV config set PGVAULT_PSQL "$SAVED_PSQL"
expect "doctor lit le fichier de config" $PV doctor
case "$($PV config show)" in *"(fichier)"*) ok "config show indique la source";; *) ko "config show indique la source";; esac
refuse "config refuse une variable inconnue" $PV config set PATH x
expect "config set URL" $PV config set PGVAULT_KEY_CMD 'psql "postgresql://u:motdepasse@h/db"'
case "$($PV config show)" in *motdepasse*) ko "config show masque le mot de passe d'URL";; *) ok "config show masque le mot de passe d'URL";; esac
expect "config unset" $PV config unset PGVAULT_KEY_CMD
export PGVAULT_PSQL=$SAVED_PSQL; unset PGVAULT_CONFIG
expect "detect local" $PV detect --json

# Capture des secrets collés dans un prompt (hook UserPromptSubmit)
FAKE_GH="ghp_$(python -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36)))')"
FAKE_OA="sk-proj-$(python -c 'import secrets;print(secrets.token_urlsafe(30))')"
FAKE_RAW="$(python -c 'import secrets;print(secrets.token_urlsafe(30))')"
cap() { python -c 'import json,sys; print(json.dumps({"hook_event_name":"UserPromptSubmit","prompt":sys.argv[1]}))' "$1" | $PV capture; }
out=$(cap "configure le déploiement avec $FAKE_GH et la clé $FAKE_OA stp")
case "$out" in *'"decision": "block"'*) ok "capture bloque le prompt";; *) ko "capture bloque le prompt";; esac
case "$out" in *"$FAKE_GH"*|*"$FAKE_OA"*) ko "capture ne renvoie pas la valeur";; *) ok "capture ne renvoie pas la valeur";; esac
case "$out" in *github_token*openai_api_key*) ok "capture nomme les clés";; *) ko "capture nomme les clés ($out)";; esac
got=$($PV run --env T=github_token -- python -c 'import os,sys; sys.stdout.write(os.environ["T"])')
[ "$got" = "$FAKE_GH" ] && ok "capture a rangé la valeur exacte" || ko "capture a rangé la valeur exacte"
out=$(cap "encore $FAKE_GH")
case "$out" in *github_token_2*) ok "capture évite d'écraser un nom";; *) ko "capture évite d'écraser un nom";; esac
out=$(cap "le secret brut $FAKE_RAW")
case "$out" in *'"decision": "block"'*) ok "capture par entropie";; *) ko "capture par entropie";; esac
out=$(cap "corrige le bug du commit 3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a dans src/app/config.ts")
[ -z "$out" ] && ok "capture laisse passer un prompt normal" || ko "capture laisse passer un prompt normal"
out=$(PGVAULT_KEY_FILE="$W/absente.key" cap "tiens $FAKE_GH")
case "$out" in *'"decision": "block"'*Non\ rang*) ok "capture bloque même si le coffre est indisponible";; *) ko "capture bloque même si le coffre est indisponible";; esac
expect "put --verify format inconnu" sh -c "printf 'valeur-sans-format-connu' | $PV put libre --verify"

# Garde-fou (hook PreToolUse)
g() { printf '{"tool_name":"Bash","tool_input":{"command":%s}}' "$1" | $PV guard >/dev/null 2>&1; }
refuse "guard bloque reveal" g '"pgvault reveal demo"'
refuse "guard bloque PGVAULT_ALLOW_REVEAL" g '"PGVAULT_ALLOW_REVEAL=1 x"'
refuse "guard bloque pgp_sym_decrypt" g '"psql -c \"select pgp_sym_decrypt(v,k)\""'
refuse "guard bloque cat de la clé" g '"cat /etc/app/vault.key"'
expect "guard laisse passer list" g '"pgvault list"'
expect "guard laisse passer run" g '"pgvault run --env A=b -- node x.js"'
expect "guard laisse passer config set KEY_CMD" g '"pgvault config set PGVAULT_KEY_CMD \"ssh h cat /etc/x/vault.key\""'
refuse "guard bloque config chaîné à une lecture" g '"pgvault config show; cat /etc/x/vault.key"'

echo "----- $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ]
