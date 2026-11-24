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

## 2026-11-24 (0.2.0)

- Compatibilité vérifiée avec le coffre d'origine : 78/78 secrets identiques ; écarts listés dans
  `docs/COMPATIBILITE.md`. Options pgcrypto alignées par défaut (`compress-algo=1`), réglables par
  `PGVAULT_PGP_OPTIONS`.
- Nouveau : `pgvault detect [--ssh hôte]`, `pgvault config`, fichier `~/.config/pgvault/config.env`,
  `/pgvault:setup` guidé par la détection (ADR 0003).
- Corrigé : E4 (cmd.exe et CRLF sous Windows).
- Preuves : 41/41 tests ; `detect --ssh` puis `doctor` et `list` OK à distance sur le coffre d'origine.

## 2026-11-24 (0.3.0)

- Capture automatique : hook `UserPromptSubmit` (`pgvault capture`) qui range au coffre tout secret collé
  dans un message et bloque le message avant le modèle (ADR 0004). `pgvault scan` pour tester la détection.
- `put --verify` : vérification auprès de GitHub, OpenAI, Anthropic ou Stripe avant écriture, comme le
  coffre d'origine.
- `/pgvault:setup` : nouvelle étape qui propose les secrets courants et les fait ranger (terminal masqué
  ou capture). Skill : tout jeton produit par une commande passe par pipe dans `pgvault put`.
- Preuves : 50/50 tests, aucun faux positif sur le texte piège. Reste : hooks en session Claude réelle
  (CLI déconnecté au moment du test).
