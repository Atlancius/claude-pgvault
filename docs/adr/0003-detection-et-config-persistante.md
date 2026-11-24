# ADR 0003 : détection de l'architecture et configuration persistante

- Date : 2026-11-24
- Statut : accepté

## Contexte

`/pgvault:setup` demandait seulement où vivait la base. Un élève ne sait pas toujours écrire une commande
`psql` derrière `docker exec` ou `ssh`.

## Décision

- `pgvault detect [--ssh hôte]` sonde, sans lire aucune valeur : `psql`, `pg_isready`, conteneurs Docker
  dont l'image est PostgreSQL, leurs bases, les tables qui ont `key` + `value_encrypted`, les fichiers de
  clé connus (chemin et droits), les hôtes de `~/.ssh/config`. Il propose `PGVAULT_PSQL`, schéma, table et
  source de clé.
- `pgvault config set|unset|show|path` enregistre la configuration dans `~/.config/pgvault/config.env`
  (droits 600, aucun secret). L'environnement prime.
- `/pgvault:setup` enchaîne : état, détection, choix guidé (AskUserQuestion), enregistrement, `init` si
  coffre neuf, preuve par `doctor`.
- Le hook laisse passer `pgvault config` et `pgvault detect` non chaînés (ils citent légitimement le
  chemin de la clé dans `PGVAULT_KEY_CMD`).

## Options écartées

- Écrire dans le profil shell de l'utilisateur : intrusif, dépend du shell.
- Assistant interactif dans le CLI (questions au clavier) : inutilisable par un agent.
