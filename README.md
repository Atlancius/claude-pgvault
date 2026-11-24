# pgvault : un coffre de secrets PostgreSQL pour Claude Code et Codex

`pgvault` range tes jetons, clés d'API et mots de passe dans une table PostgreSQL, chiffrés par
`pgcrypto` (`pgp_sym_encrypt`, AES-256). Ton agent peut lister les secrets, vérifier qu'ils existent et
les passer à un programme, **sans jamais voir une valeur** : elles n'apparaissent ni dans la conversation,
ni dans les logs, ni dans un fichier.

Le plugin contient :

- l'outil `pgvault` (Python 3.8+, bibliothèque standard, aucune dépendance) ;
- un skill qui apprend à l'agent à s'en servir correctement ;
- trois commandes : `/pgvault:doctor`, `/pgvault:list` et `/pgvault:setup`, qui détecte ta base (locale,
  Docker ou serveur SSH), trouve un coffre et une clé existants, te fait choisir puis vérifie ;
- un hook qui bloque les commandes qui afficheraient un secret ou la clé maître.

## Ce qu'il te faut

- Une base PostgreSQL 12+ avec l'extension `pgcrypto` (incluse dans PostgreSQL), en local, dans un
  conteneur Docker ou sur un serveur joignable en SSH.
- `psql` là où la commande s'exécute (machine locale, conteneur ou serveur).
- Python 3.8+ et `sh` (Git Bash sous Windows, livré avec Git).

## Installation

### Claude Code

Dans Claude Code :

```
/plugin marketplace add Atlancius/claude-pgvault
/plugin install pgvault@pgvault
```

Ou depuis un terminal :

```
claude plugin marketplace add Atlancius/claude-pgvault
claude plugin install pgvault@pgvault
```

Redémarre Claude Code, puis lance `/pgvault:doctor`.

### Codex (ou tout autre agent)

```
git clone https://github.com/Atlancius/claude-pgvault ~/.pgvault
mkdir -p ~/.codex/skills && cp -r ~/.pgvault/skills/pgvault ~/.codex/skills/
ln -s ~/.pgvault/bin/pgvault ~/.local/bin/pgvault   # ou ajoute ~/.pgvault/bin à ton PATH
```

Sous Windows (PowerShell), ajoute `%USERPROFILE%\.pgvault\bin` au PATH : `pgvault.cmd` est fourni.

## Configuration

Le plus simple : lance `/pgvault:setup` dans Claude Code. À la main :

```sh
pgvault detect                    # cette machine : psql, PostgreSQL local, conteneurs, coffres, clés, hôtes SSH
pgvault detect --ssh mon-serveur  # même chose sur un serveur
pgvault config set PGVAULT_PSQL "docker exec -i mon-postgres psql -U app -d app"
pgvault config set PGVAULT_KEY_FILE ~/.config/pgvault/vault.key
pgvault config show
```

`pgvault config` écrit `~/.config/pgvault/config.env` (droits 600, aucun secret). Les variables
d'environnement (voir `.env.example`) priment sur ce fichier. Rien n'est écrit en dur.

| Variable | Rôle | Défaut |
|---|---|---|
| `PGVAULT_PSQL` | commande qui lance `psql` et lit le SQL sur l'entrée standard | `psql` |
| `PGVAULT_KEY_FILE` | fichier qui contient la clé maître (droits `600`) | aucun |
| `PGVAULT_KEY_CMD` | à défaut, commande qui imprime la clé (ex. gestionnaire de mots de passe) | aucun |
| `PGVAULT_SCHEMA` | schéma du coffre | `vault` |
| `PGVAULT_TABLE` | table du coffre | `secrets` |
| `PGVAULT_PGP_OPTIONS` | options `pgp_sym_encrypt` | `cipher-algo=aes256,compress-algo=1` |
| `PGVAULT_CONFIG` | chemin du fichier de configuration | `~/.config/pgvault/config.env` |

Exemples de `PGVAULT_PSQL` :

```sh
export PGVAULT_PSQL='psql "postgresql://app@localhost:5432/app"'          # base locale
export PGVAULT_PSQL='docker exec -i mon-postgres psql -U app -d app'       # conteneur Docker
export PGVAULT_PSQL='ssh mon-serveur docker exec -i mon-postgres psql -U app -d app'   # serveur distant
```

Avec `ssh`, la clé maître est stockée sur ta machine (ou sort de ton gestionnaire via `PGVAULT_KEY_CMD`),
jamais sur le serveur : elle n'y passe qu'en mémoire, dans le tunnel SSH, le temps de la requête.
Tu peux aussi garder la clé sur le serveur et y lancer `pgvault` directement.

## Premier coffre

Dans **ton** terminal (pas dans la conversation avec l'agent) :

```sh
mkdir -p ~/.config/pgvault && chmod 700 ~/.config/pgvault
( umask 077; openssl rand -base64 48 > ~/.config/pgvault/vault.key )
export PGVAULT_KEY_FILE=~/.config/pgvault/vault.key
export PGVAULT_PSQL='psql "postgresql://app@localhost:5432/app"'
pgvault init
pgvault doctor
```

Sauvegarde la clé à part de la base. Sans elle, les secrets sont perdus. Avec elle et une copie de la
base, ils sont lisibles.

## Usage

```sh
pgvault put stripe_secret_key --description "Stripe prod" --expires-at 2027-06-30   # saisie masquée
pgvault list                       # noms, expirations, descriptions ; jamais les valeurs
pgvault has stripe_secret_key      # présent ou absent, avec la longueur
pgvault run --env STRIPE_KEY=stripe_secret_key -- node scripts/sync.js
pgvault expiring --days 30         # jetons à renouveler
pgvault rm vieux_jeton --yes       # définitif
```

`put` lit la valeur sur l'entrée standard : `pbpaste | pgvault put ...` (macOS),
`Get-Clipboard | pgvault put ...` (PowerShell), ou une commande qui imprime le nouveau jeton.
Ne passe jamais une valeur en argument : elle resterait dans l'historique du shell.

`pgvault reveal <clé>` affiche une valeur, uniquement si tu poses toi-même `PGVAULT_ALLOW_REVEAL=1`
dans ton terminal. Le hook du plugin interdit cette commande à l'agent.

## Ce que l'agent peut et ne peut pas faire

| Autorisé | Bloqué par le hook |
|---|---|
| `pgvault doctor`, `list`, `has`, `expiring` | `pgvault reveal`, `PGVAULT_ALLOW_REVEAL` |
| `pgvault run --env ... -- commande` | `pgp_sym_decrypt` en SQL direct |
| `pgvault put` avec une valeur venant d'un programme | lecture du fichier de clé (`cat`, `type`, `Get-Content`...) |

Le hook arrête les fuites évidentes. Il ne protège pas d'un programme lancé par `run` qui
imprimerait lui-même son secret : lance seulement des commandes que tu connais.

## Format du coffre

```sql
CREATE TABLE vault.secrets (
  key text PRIMARY KEY,
  value_encrypted bytea NOT NULL,       -- pgp_sym_encrypt(valeur, clé, 'cipher-algo=aes256,compress-algo=1')
  description text NOT NULL DEFAULT '',
  expires_at timestamptz,
  source text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);
```

Un coffre existant au même principe (`key`, `value_encrypted`) fonctionne tel quel : `pgvault` détecte les
colonnes présentes et remplit `source` et les horodatages obligatoires.

## Sécurité, en clair

- La clé maître voyage dans le SQL envoyé à `psql` par l'entrée standard, jamais en argument : elle
  n'apparaît pas dans la liste des processus. Si ton serveur journalise toutes les requêtes
  (`log_statement = 'all'`), elle y serait écrite : garde `log_statement` à `none` ou `ddl`.
- Les erreurs de `psql` sont nettoyées avant affichage (contexte SQL retiré, hexadécimal masqué).
- Les noms de schéma et de table sont validés ; les noms et valeurs de secrets voyagent en hexadécimal.
- Le chiffrement est fait par PostgreSQL : la valeur claire passe par la connexion. Utilise une connexion
  locale, un socket, un tunnel SSH ou TLS.

## Tests

```sh
sh tests/run-tests.sh   # crée un PostgreSQL jetable (initdb), 41 vérifications, puis l'arrête
```

## Licence

MIT. Voir [LICENSE](LICENSE). Documentation du projet : [docs/](docs/) et [JOURNAL.md](JOURNAL.md).
