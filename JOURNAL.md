# Journal

## 2026-11-24

- Création de pgvault 0.1.0 : CLI Python stdlib, skill, commandes `doctor` / `list` / `setup`, hook
  `PreToolUse`, manifests plugin et marketplace Claude Code.
- Modèle : coffre PostgreSQL + pgcrypto (`key`, `value_encrypted` en `pgp_sym_encrypt`), clé maître dans
  un fichier 600, accès par `psql` (local, `docker exec`, `ssh`).
- Corrigé : E1, E2, E3 (voir `docs/ERREURS.md`).
- Preuves : 29/29 tests locaux ; `doctor` OK sur un coffre réel au même format (lecture seule) ;
  `claude plugin validate` OK.
