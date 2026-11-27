# Registre des essais

| Date | Essai | Recette | Résultat | Verdict |
|---|---|---|---|---|
| 2026-11-24 | Suite locale v1 | `sh tests/run-tests.sh`, PostgreSQL 18.3 `initdb` jetable, Python 3.14.3, Git Bash | 27/29 (E3, encodage des tests) | corrigé |
| 2026-11-24 | Suite locale v2 | idem | 29/29 PASS | retenu |
| 2026-11-24 | `doctor` sur coffre réel (lecture seule) | PostgreSQL 17.11 en conteneur, `PGVAULT_PSQL='docker exec -i <conteneur> sh -lc "psql ..."'` | plantage (E1) puis verdict OK, déchiffrement vérifié | retenu |
| 2026-11-24 | `claude plugin validate .` | Claude Code 2.1.295 | Validation passed | retenu |
| 2026-11-24 | Installation propre depuis le README | `CLAUDE_CONFIG_DIR` vide, `claude plugin marketplace add Atlancius/claude-pgvault` puis `claude plugin install pgvault@pgvault` | installé ; inventaire 4 skills + 1 hook ; 29/29 depuis la copie installée ; fins de ligne LF | retenu |
| 2026-11-24 | Clone Linux propre | `git clone` dans un dossier temporaire, `sh bin/pgvault --version`, hook sur `pgvault reveal` | version OK, hook code 2 | retenu |
| 2026-11-24 | Hook en session Claude réelle (`claude -p --plugin-dir`) | Claude Code 2.1.295 | non joué : session OAuth du CLI expirée | à refaire |
| 2026-11-24 | Comparaison complète avec le coffre d'origine | lecture des 78 secrets par pgvault et par le module d'origine, comparaison en mémoire | 78/78 identiques, aucune valeur affichée | retenu |
| 2026-11-24 | `detect --ssh` v1 depuis Windows | Git Bash, Python 3.14.3 | Docker non vu (E4) | corrigé |
| 2026-11-24 | `detect --ssh` v2 + `config set` + `doctor` à distance | `PGVAULT_KEY_CMD` par SSH | coffre, bases, clé trouvés ; doctor OK ; list 78 | retenu |
| 2026-11-24 | Suite locale v3 | `sh tests/run-tests.sh` | 41/41 PASS | retenu |
| 2026-11-24 | Détection des secrets v1 | `pgvault scan` sur faux jetons et sur texte piège (empreinte git, UUID, chemin, URL, sha256, base64 court, mot long) | 4/4 détectés, 0 faux positif | retenu |
| 2026-11-24 | Suite locale v4 (capture) | `sh tests/run-tests.sh` | 50/50 PASS | retenu |
| 2026-11-24 | Hooks en session Claude réelle | `claude -p` avec le plugin | non joué : CLI déconnecté (`loggedIn: false`) | à refaire |
| 2026-11-24 | Capture en session réelle v1 | `claude -p` (Claude Code 2.1.295, Haiku), réglages du poste de développement | rien rangé : un masqueur déjà installé passe avant (E5) | expliqué |
| 2026-11-24 | Capture en session réelle v2 | `claude -p --setting-sources project`, sans plugins tiers, faux `ghp_` | bloqué, 0 tour, 0 $, rangé à l'identique ; jeton resté dans la transcription locale (E6) | corrigé |
| 2026-11-24 | Capture en session réelle v3 (nettoyage) | idem, faux `sk-proj-` | bloqué, 0 tour, 0 $, rangé à l'identique, 0 occurrence restante dans la transcription | retenu |
| 2026-11-24 | Garde-fou en session réelle | `claude -p --allowedTools Bash`, `pgvault reveal` et lecture du fichier de clé | les deux bloqués par le hook ; `pgvault run` passe (longueur 62) ; ni jeton ni clé dans la sortie ou la transcription | retenu |
| 2026-11-24 | Suite locale v5 | `sh tests/run-tests.sh` | 52/52 PASS | retenu |
| 2026-11-27 | Suite locale v6 (0.3.2) | `sh tests/run-tests.sh`, PostgreSQL 18 `initdb` jetable | 52/52 PASS | retenu |
| 2026-11-27 | `claude plugin validate --strict` | Claude Code 2.1.295, `.` et `.claude-plugin/plugin.json` | Validation passed (x2) | retenu |
| 2026-11-27 | Installation Codex depuis le clone | Codex CLI 0.172.0, `CODEX_HOME` jetable, `codex plugin marketplace add <clone>` puis `codex plugin add pgvault@pgvault` | installé en 0.3.2, skill présent ; marketplace racine `path: "./"` acceptée | retenu |
