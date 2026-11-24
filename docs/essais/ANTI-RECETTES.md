# Anti-recettes

- Ajouter des options après une commande configurable par l'utilisateur : perdues derrière `sh -c`.
  Signe d'alerte : en-têtes de colonnes dans la sortie. Alternative : préambule `\set` / `\pset`.
- Exposer un `get` qui imprime la valeur : la valeur entre dans la transcription de l'agent.
  Alternative : `pgvault run`.
- Afficher le `stderr` brut de `psql` : il peut citer la requête, donc la clé. Alternative : nettoyage.
- `subprocess.run(ligne_posix, shell=True)` sous Windows : passe par cmd.exe. Signe d'alerte : une
  commande qui marche dans Git Bash échoue depuis Python. Alternative : `[sh, "-c", ligne]` et entrée en octets.
