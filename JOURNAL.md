# Journal

## 2026-11-24

- Création de pgvault 0.1.0 : CLI Python stdlib, skill, commandes `doctor` / `list` / `setup`, hook
  `PreToolUse`, manifests plugin et marketplace Claude Code.
- Modèle : coffre PostgreSQL + pgcrypto (`key`, `value_encrypted` en `pgp_sym_encrypt`), clé maître dans
  un fichier 600, accès par `psql` (local, `docker exec`, `ssh`).
- Corrigé : E1, E2, E3 (voir `docs/ERREURS.md`).
- Preuves : 29/29 tests locaux ; `doctor` OK sur un coffre réel au même format (lecture seule) ;
  `claude plugin validate` OK.
- Dépôt public `Atlancius/claude-pgvault` créé ; gitleaks (arbre et historique) : aucune fuite ; relecture
  manuelle : aucune IP, aucun domaine, aucun hôte, aucun nom de conteneur. Commits signés de l'adresse
  noreply GitHub.
- Installation testée sur un profil Claude Code vierge et sur un clone Linux propre (voir le registre des essais).
- Publié sur la marketplace Ottho Academy (`plugin-pgvault`, étagère agent, cibles Claude et Codex),
  image = aperçu social GitHub du dépôt.
- Reste : test du hook dans une session Claude réelle (CLI non authentifié au moment du test).
