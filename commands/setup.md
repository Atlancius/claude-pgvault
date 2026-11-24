---
description: Met en place un coffre pgvault neuf ou branche un coffre existant
allowed-tools: Bash
---

Suis la section « Mettre en place un coffre neuf » du skill `pgvault`.

1. Demande à l'utilisateur où vit sa base PostgreSQL (locale, conteneur Docker, serveur SSH) et construis
   avec lui `PGVAULT_PSQL`. Ne devine aucun hôte.
2. La clé maître se génère dans son terminal à lui, jamais dans la conversation ; donne-lui la commande.
3. Fais-lui exporter `PGVAULT_PSQL` et `PGVAULT_KEY_FILE`, puis lance `pgvault init` (coffre neuf seulement)
   et `pgvault doctor`.
4. Rappelle de sauvegarder la clé à part de la base.
