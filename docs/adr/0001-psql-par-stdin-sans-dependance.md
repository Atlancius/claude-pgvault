# ADR 0001 : parler à PostgreSQL par `psql` sur l'entrée standard, sans dépendance Python

- Date : 2026-11-24
- Statut : accepté

## Contexte

Le plugin doit marcher chez des élèves dont la base vit en local, dans un conteneur Docker ou sur un VPS
joignable en SSH, depuis Claude Code ou Codex, sous macOS, Linux ou Windows.

## Décision

`pgvault` construit le SQL et l'envoie sur l'entrée standard d'une commande configurable
(`PGVAULT_PSQL`). Les options de sortie sont posées en tête du SQL (`\set`, `\pset`) pour s'appliquer même
quand `psql` est enveloppé (`sh -c`, `docker exec`, `ssh`). Les chaînes voyagent en hexadécimal
(`convert_from(decode(...,'hex'),'UTF8')`) : aucun échappement de guillemets.

## Options écartées

- `psycopg` / `asyncpg` : dépendance à installer, ne traverse ni `docker exec` ni `ssh` sans tunnel.
- Serveur MCP : processus permanent et configuration de plus, alors qu'un CLI suffit et marche aussi
  dans Codex et dans un terminal humain.
- Chiffrement côté client (Fernet, age) : incompatible avec les coffres pgcrypto existants et ajoute une
  dépendance.

## Conséquences

- La clé maître passe dans le texte SQL : elle n'apparaît pas dans la liste des processus, mais un
  serveur en `log_statement = 'all'` la journaliserait. Documenté dans le README.
- Les erreurs `psql` sont nettoyées (lignes `LINE`, `QUERY`, hexadécimal masqué) avant affichage.
