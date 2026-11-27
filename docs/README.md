# Documentation de pgvault

- Stack : Python 3.8+ (bibliothèque standard), `psql` (client PostgreSQL), PostgreSQL 12+ avec `pgcrypto`,
  `sh` POSIX pour le lanceur et le hook. Testé avec Python 3.14.3, PostgreSQL 18.3 (local, Windows) et
  PostgreSQL 17.11 (conteneur Alpine, Linux), Claude Code 2.1.295, Codex CLI 0.172.0.
- Manifestes : Claude Code (`.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`) et Codex
  (`.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, skill seulement), version identique partout.
- Décisions : [adr/](adr/).
- Essais et rendus : [essais/REGISTRE-ESSAIS.md](essais/REGISTRE-ESSAIS.md), recettes
  [essais/RECETTES.md](essais/RECETTES.md), anti-recettes [essais/ANTI-RECETTES.md](essais/ANTI-RECETTES.md).
- Erreurs rencontrées : [ERREURS.md](ERREURS.md).
- Compatibilité avec le coffre d'origine : [COMPATIBILITE.md](COMPATIBILITE.md).
- Historique : [../JOURNAL.md](../JOURNAL.md).
