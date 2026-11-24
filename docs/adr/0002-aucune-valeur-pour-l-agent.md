# ADR 0002 : l'agent ne voit jamais une valeur

- Date : 2026-11-24
- Statut : accepté

## Décision

- Les commandes agent (`doctor`, `list`, `has`, `expiring`, `run`) n'impriment que des noms, des dates et
  des longueurs.
- Les secrets atteignent un programme par `pgvault run --env VAR=clé -- commande` (variables
  d'environnement du processus enfant).
- `reveal` exige `PGVAULT_ALLOW_REVEAL=1`, retiré de l'environnement de `run`, et bloqué par le hook.
- `put` lit la valeur sur l'entrée standard (saisie masquée si terminal), jamais en argument.
- Hook `PreToolUse` (Bash, PowerShell) : bloque `reveal`, `PGVAULT_ALLOW_REVEAL`, `pgp_sym_decrypt` et la
  lecture du fichier de clé.

## Options écartées

- `get` qui imprime la valeur : la valeur finirait dans la transcription de l'agent.
- Écrire les secrets dans un `.env` temporaire : fichier à nettoyer, risque de commit.

## Limite assumée

Le hook vise les fuites évidentes ; un programme lancé par `run` peut toujours imprimer son secret.
