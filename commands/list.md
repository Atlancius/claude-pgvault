---
description: Liste les noms des secrets du coffre pgvault (jamais les valeurs)
argument-hint: "[préfixe]"
allowed-tools: Bash
---

Lance `"${CLAUDE_PLUGIN_ROOT}/bin/pgvault" list --prefix "$ARGUMENTS"` (sans `--prefix` si aucun argument),
puis `"${CLAUDE_PLUGIN_ROOT}/bin/pgvault" expiring --days 30`. Présente les noms, descriptions et
expirations proches. Aucune valeur.
