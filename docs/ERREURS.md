# Registre des erreurs

## E1 (2026-11-24) : options psql perdues derrière `sh -lc`

- Symptôme : `doctor` sur un coffre réel plante (`ValueError: not enough values to unpack`) ; la sortie
  contient des en-têtes de colonnes.
- Cause racine : les options `-At -q` ajoutées à `PGVAULT_PSQL` deviennent `$0 $1...` de `sh -lc '...'`
  et ne vont pas à `psql`.
- Correctif : options répétées en tête du SQL (`\set QUIET on`, `\pset format unaligned`,
  `\pset tuples_only on`, `\set ON_ERROR_STOP on`).
- Preuve : `doctor` OK sur un coffre réel derrière `docker exec ... sh -lc 'psql ...'` ; 29/29 tests locaux.
- Du premier coup : ne jamais compter sur des arguments ajoutés à une commande configurable ; passer
  les réglages dans le flux lui-même.

## E2 (2026-11-24) : socket Unix trop long pour le cluster de test

- Symptôme : `pg_ctl` ne démarre pas, « chemin du socket ... trop long (maximum 107 octets) ».
- Cause racine : `-k <dossier de test>` dans un chemin profond.
- Correctif : `-c unix_socket_directories=` et connexion TCP sur `localhost`.
- Preuve : la suite démarre et passe.

## E3 (2026-11-24) : faux échecs d'encodage dans les tests

- Symptôme : longueur 29 attendue 30 ; valeur avec `é` différente après `run`.
- Cause racine : `${#VAR}` compte des octets dans `sh` ; `print` Python sous Windows sort en cp1252.
- Correctif : longueur attendue en dur ; l'enfant écrit en UTF-8 sur `sys.stdout.buffer`.

## E4 (2026-11-24) : sous Windows, les sous-commandes passaient par cmd.exe et en CRLF

- Symptôme : `detect --ssh` ne voyait ni Docker ni les conteneurs ; sonde en erreur
  « syntax error: unexpected word (expecting "do") ».
- Cause racine : `subprocess.run(..., shell=True)` utilise cmd.exe sous Windows (guillemets simples non
  compris) ; le mode texte transforme `
` en `
` sur l'entrée standard, ce que `sh` refuse.
- Correctif : toutes les commandes passent par `sh -c` quand `sh` existe (Git Bash), entrée et sortie en
  octets UTF-8, `
` normalisé en sortie.
- Preuve : `detect --ssh` trouve conteneur, bases, coffre et clé ; `doctor` OK depuis Windows en SSH ;
  41/41 tests.
- Du premier coup : sous Windows, ne jamais confier une ligne POSIX à `shell=True` ni du texte à stdin.

## E5 (2026-11-24) : capture inopérante quand un autre masqueur passe avant

- Symptôme : en session réelle, rien n'est rangé ; le modèle reçoit `[REDACTED-SECRET-...]`.
- Cause racine : un autre plugin chargé par `CLAUDE_CODE_PLUGIN_DIRS` masque les secrets du prompt avant
  les hooks ; pgvault ne voit plus la valeur.
- Correctif : documenté (garder un seul masqueur) ; test réel fait sans ce plugin, comme chez un élève.
- Preuve : sans lui, prompt bloqué, 0 tour, 0 $, valeur rangée à l'identique.

## E6 (2026-11-24) : valeur bloquée restée dans la transcription locale

- Symptôme : après blocage, le jeton figure deux fois dans le fichier `.jsonl` de la session.
- Cause racine : Claude Code journalise le prompt (file d'attente, message « Original prompt ») après le hook.
- Correctif : processus détaché `pgvault scrub` qui remplace la valeur par `[pgvault:<nom>]` (transcription
  et `history.jsonl`).
- Preuve : session réelle, 0 occurrence restante ; test automatique ajouté.
