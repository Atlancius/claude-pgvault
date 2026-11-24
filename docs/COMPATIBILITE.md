# Compatibilité avec le coffre d'origine

pgvault reprend le format d'un coffre PostgreSQL + pgcrypto déjà en production (déploiement d'origine,
non publié). Vérifié le 2026-11-24 en lecture seule sur ce coffre (78 secrets).

## Identique

| Point | Coffre d'origine | pgvault |
|---|---|---|
| Stockage | table `vault.secrets`, colonnes `key text` (clé primaire), `value_encrypted bytea` | même table par défaut, détectée par `detect` |
| Chiffrement | `pgp_sym_encrypt(valeur, clé, 'cipher-algo=aes256,compress-algo=1')` | mêmes options par défaut (`PGVAULT_PGP_OPTIONS`) |
| Déchiffrement | `pgp_sym_decrypt(value_encrypted, clé)` | identique |
| Clé maître | fichier `600`, lu puis `strip()` | `PGVAULT_KEY_FILE` (ou `PGVAULT_KEY_CMD`), `strip()` |
| Passage de la clé | texte SQL, en hexadécimal (`convert_from(decode(..., 'hex'), 'UTF8')`), sur l'entrée de `psql` | identique |
| Accès | `docker exec -i <conteneur> sh -lc 'psql ...'` | `PGVAULT_PSQL`, même commande possible |
| Écriture | `INSERT ... ON CONFLICT (key) DO UPDATE` | identique |
| Horodatage d'écriture | colonne obligatoire mise à `now()` | toute colonne horodatée obligatoire sans défaut mise à `now()` |

Preuve : les 78 secrets déchiffrés par pgvault sont identiques, octet pour octet, à ceux du module de
lecture d'origine (comparaison en mémoire, aucune valeur affichée). `doctor` et `list` OK, depuis le
serveur et depuis un poste distant en SSH. Test croisé dans `tests/run-tests.sh` (un outil externe écrit,
pgvault lit ; pgvault écrit, un `pgp_sym_decrypt` direct lit).

## Écarts (voulus)

| Point | Coffre d'origine | pgvault | Raison |
|---|---|---|---|
| Valeur écrite | `strip()` des deux côtés | seul le saut de ligne final est retiré | garder une valeur exacte (espaces significatifs) |
| Description absente à l'écriture | remplacée par une chaîne vide | description existante conservée | ne pas effacer une information |
| `source` | `vault-put` | `pgvault` | traçabilité de l'outil |
| `expires_at` | non renseignée à l'écriture | `--expires-at` | suivi des renouvellements (`expiring`) |
| Table neuve (`init`) | colonnes historiques de migration (`old_updated_at`, `migrated_at`) | `source`, `updated_at` avec défauts | schéma propre ; pgvault lit et écrit les deux |
| Commandes | écriture (`vault-put`) et lecture par bibliothèque | `init`, `doctor`, `detect`, `config`, `list`, `has`, `put`, `run`, `expiring`, `rm`, `reveal` | usage agent sans afficher de valeur |
| Capture | saisie masquée + vérification auprès du fournisseur avant écriture (script dédié par service) ; jetons renouvelés écrits directement par le programme | `put` masqué, `put --verify` (GitHub, OpenAI, Anthropic, Stripe), capture des secrets collés dans un prompt, pipe d'une commande vers `put` | même principe, généralisé |
| Noms de clé | libres | `[A-Za-z0-9_.:/@-]`, 200 caractères | validation ; tous les noms existants passent |
