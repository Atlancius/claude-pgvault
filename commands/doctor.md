---
description: Vérifie le coffre pgvault (configuration, connexion, clé, table) sans afficher de valeur
allowed-tools: Bash
---

Lance `"${CLAUDE_PLUGIN_ROOT}/bin/pgvault" doctor` et résume le verdict. Pour chaque ligne `FAIL`,
donne la correction exacte (variable d'environnement à définir, `pgvault init`, droits de la clé).
N'affiche aucune valeur de secret.
