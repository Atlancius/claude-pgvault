---
description: Détecte où vit ta base (locale, Docker, serveur SSH), branche un coffre existant ou en crée un, puis vérifie
argument-hint: "[hôte SSH]"
allowed-tools: Bash, AskUserQuestion
---

Tu configures pgvault pour l'utilisateur. Tu détectes d'abord, tu proposes ensuite, tu ne devines jamais.
`PV` = `"${CLAUDE_PLUGIN_ROOT}/bin/pgvault"`. Aucune valeur de secret ni clé ne doit apparaître.

1. **État actuel.** Lance `PV config show` puis `PV doctor`. Si le verdict est OK, dis-le et demande
   seulement s'il veut changer de coffre ; sinon arrête-toi là.

2. **Détection locale.** Lance `PV detect`. Elle liste : psql, serveur PostgreSQL local, conteneurs
   Docker PostgreSQL, bases, tables de coffre existantes (colonnes `key` + `value_encrypted`), fichiers de
   clé trouvés et leurs droits, hôtes de `~/.ssh/config`, variables déjà définies.

3. **Choisir où chercher.** Si `$ARGUMENTS` nomme un hôte, utilise-le. Sinon, pose une question
   (AskUserQuestion) avec les options réellement détectées : « cette machine » si une base locale ou un
   conteneur existe, chaque hôte SSH listé (4 au maximum, les plus probables d'abord), « autre ».
   Pour un hôte SSH, lance `PV detect --ssh <hôte>`.

4. **Choisir le coffre.** Présente les suggestions de `detect` (coffre existant d'abord, puis nouveau
   coffre dans un conteneur, base locale, `DATABASE_URL`) et fais choisir l'utilisateur. Aucune base
   détectée : explique les trois architectures (base locale, conteneur Docker, serveur SSH) et aide-le à
   écrire sa commande `psql`, ou propose d'installer PostgreSQL.

5. **Choisir la clé maître.**
   - Clé détectée sur le serveur (`detect` l'affiche) : propose `PGVAULT_KEY_CMD=ssh <hôte> cat <chemin>`
     (la clé reste stockée sur le serveur) ; sinon, si pgvault tourne sur le serveur, `PGVAULT_KEY_FILE`.
   - Clé locale détectée : `PGVAULT_KEY_FILE=<chemin>` ; si `detect` la signale trop ouverte, donne
     `chmod 600 <chemin>`.
   - Aucune clé (coffre neuf) : l'utilisateur la génère lui-même dans son terminal, jamais toi :
     `mkdir -p ~/.config/pgvault && ( umask 077; openssl rand -base64 48 > ~/.config/pgvault/vault.key )`.
     Attends sa confirmation.
   - Coffre existant sans clé trouvée : demande où est la clé ; sans elle, rien n'est lisible.

6. **Enregistrer.** Avec l'accord de l'utilisateur, une commande par variable :
   `PV config set PGVAULT_PSQL "<commande>"`, `PV config set PGVAULT_KEY_FILE "<chemin>"` ou
   `PV config set PGVAULT_KEY_CMD "<commande>"`, et `PGVAULT_SCHEMA` / `PGVAULT_TABLE` si le coffre n'est
   pas `vault.secrets`. Le fichier (`PV config path`) ne contient aucun secret ; les variables
   d'environnement le remplacent si elles sont définies.

7. **Créer si besoin.** Coffre neuf seulement, après confirmation : `PV init`.

8. **Prouver.** `PV doctor` doit finir sur `verdict : OK`, puis `PV list`. En cas de `FAIL`, corrige la
   ligne en cause et recommence (3 essais au plus, puis explique ce qui bloque).

9. **Conclure** en trois lignes : où est le coffre, d'où vient la clé, et le rappel de sauvegarder la clé
   à part de la base.
