---
name: pgvault
description: Uses a PostgreSQL + pgcrypto secrets vault through the pgvault CLI - list secret names, check presence, inject secrets into a command as env vars, set up the vault, flag expiring tokens - without ever printing a value. Use on "vault", "coffre", "secret", "token", "API key", "pgvault", or when a command needs a credential.
---

# pgvault : utiliser le coffre sans voir les secrets

Le coffre est une table PostgreSQL (`vault.secrets` par défaut). Chaque valeur est chiffrée par
`pgp_sym_encrypt` (pgcrypto, AES-256) avec une clé maître qui reste dans un fichier `600`.
L'outil `pgvault` lit, écrit et injecte les secrets ; aucune commande agent n'affiche une valeur.

## Trouver l'outil

- Plugin Claude Code : `"${CLAUDE_PLUGIN_ROOT}/bin/pgvault"` (ou `pgvault` s'il est dans le PATH).
- Codex ou installation manuelle : `pgvault` dans le PATH, sinon `python3 <dépôt>/scripts/pgvault.py`.
- Windows sans `sh` : `bin\pgvault.cmd`.

Toujours commencer par `pgvault doctor`. S'il échoue, lire la ligne `FAIL` et corriger la configuration
avant toute autre commande.

## Configuration (variables d'environnement, jamais en dur)

| Variable | Rôle |
|---|---|
| `PGVAULT_PSQL` | commande psql qui lit le SQL sur l'entrée standard (défaut `psql`) |
| `PGVAULT_KEY_FILE` | fichier de la clé maître (droits 600) |
| `PGVAULT_KEY_CMD` | à défaut, commande qui imprime la clé (gestionnaire de mots de passe) |
| `PGVAULT_SCHEMA`, `PGVAULT_TABLE` | emplacement du coffre (défaut `vault.secrets`) |

Exemples de `PGVAULT_PSQL` : `psql "$DATABASE_URL"`, `docker exec -i mon-postgres psql -U app -d app`,
`ssh mon-serveur docker exec -i mon-postgres psql -U app -d app`.

Si la configuration manque, demander à l'utilisateur où vit sa base et sa clé ; ne jamais deviner un hôte.

## Gestes

| Besoin | Commande |
|---|---|
| état complet | `pgvault doctor` |
| créer le coffre | `pgvault init` |
| noms des secrets | `pgvault list [--prefix stripe_]` |
| un secret existe ? | `pgvault has stripe_secret_key` (longueur seulement) |
| utiliser des secrets | `pgvault run --env STRIPE_KEY=stripe_secret_key -- node script.js` |
| expirations proches | `pgvault expiring --days 30` |
| supprimer | `pgvault rm <clé> --yes`, après accord explicite de l'utilisateur |

## Écrire un secret

La valeur ne doit jamais passer par la conversation ni par un argument de commande.

- L'utilisateur la saisit lui-même dans son terminal : `pgvault put openai_api_key --description "clé projet X"`
  (saisie masquée), ou `pbpaste | pgvault put ...` / `Get-Clipboard | pgvault put ...`.
- Si la valeur sort d'un programme (rotation d'un jeton), la rediriger directement :
  `nouvelle-commande-qui-imprime-le-jeton | pgvault put meta_token --expires-at 2027-01-15`.
- Si l'utilisateur colle un secret dans le chat : ne pas le réutiliser, lui dire qu'il est exposé,
  lui conseiller de le révoquer puis de l'écrire lui-même avec `pgvault put`.

## Interdits

- `pgvault reveal` et `PGVAULT_ALLOW_REVEAL` : réservés à l'humain dans son propre terminal.
- Lire le fichier de clé (`cat`, `type`, `Get-Content`, copie) ou appeler `pgp_sym_decrypt` en SQL direct.
- `echo $VAR` d'une variable injectée, `env`, `printenv` ou `set` dans une commande lancée par `pgvault run`.
- Écrire une valeur dans un fichier, un log, un commit, un prompt ou une sortie d'outil.

Le hook du plugin bloque les cas évidents ; il ne remplace pas ces règles.

## Mettre en place un coffre neuf

1. Générer une clé hors conversation, dans le terminal de l'utilisateur :
   `umask 077; openssl rand -base64 48 > ~/.config/pgvault/vault.key` (créer le dossier avant).
2. Exporter `PGVAULT_PSQL` et `PGVAULT_KEY_FILE` (profil shell ou `.env` jamais versionné).
3. `pgvault init`, puis `pgvault doctor`.
4. Sauvegarder la clé à part de la base : sans elle, les secrets sont perdus ; avec elle et un dump,
   ils sont lisibles.

Coffre existant au même format (`key text`, `value_encrypted bytea`) : `pgvault` s'adapte aux colonnes
présentes (`description`, `expires_at`, `source`, horodatages obligatoires).
