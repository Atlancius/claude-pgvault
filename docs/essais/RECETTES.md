# Recettes

## Tester contre un PostgreSQL jetable sans Docker

`initdb -U pgv -A trust` dans un dossier temporaire, `pg_ctl -o "-p 55432 -c unix_socket_directories= -c listen_addresses=localhost" -w start`,
connexion TCP. Arrêt par `trap` en sortie. Voir `tests/run-tests.sh`.

## Brancher un coffre derrière un conteneur

`PGVAULT_PSQL='docker exec -i <conteneur> sh -lc "psql -U \"\$POSTGRES_USER\" -d <base>"'` : les variables
du conteneur restent dans le conteneur ; les options psql viennent du préambule SQL.
