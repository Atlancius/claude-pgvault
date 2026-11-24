# Registre des essais

| Date | Essai | Recette | Résultat | Verdict |
|---|---|---|---|---|
| 2026-11-24 | Suite locale v1 | `sh tests/run-tests.sh`, PostgreSQL 18.3 `initdb` jetable, Python 3.14.3, Git Bash | 27/29 (E3, encodage des tests) | corrigé |
| 2026-11-24 | Suite locale v2 | idem | 29/29 PASS | retenu |
| 2026-11-24 | `doctor` sur coffre réel (lecture seule) | PostgreSQL 17.11 en conteneur, `PGVAULT_PSQL='docker exec -i <conteneur> sh -lc "psql ..."'` | plantage (E1) puis verdict OK, déchiffrement vérifié | retenu |
| 2026-11-24 | `claude plugin validate .` | Claude Code 2.1.295 | Validation passed | retenu |
| 2026-11-24 | Installation propre depuis le README | voir JOURNAL.md | voir JOURNAL.md | voir JOURNAL.md |
