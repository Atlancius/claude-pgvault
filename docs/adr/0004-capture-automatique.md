# ADR 0004 : capture automatique des secrets collés dans un prompt

- Date : 2026-11-24
- Statut : accepté

## Contexte

Un élève colle souvent un jeton dans la conversation. Sans garde-fou, la valeur part au modèle et reste
dans la transcription.

## Décision

- Hook `UserPromptSubmit` (`pgvault capture`) : détection par formats connus, par affectation
  (`token: ...`) et par entropie (32+ caractères, trois classes, entropie >= 4,3 bits, hors hexadécimal
  pur et chemins). Chaque secret est rangé au coffre (`source = pgvault-capture`, description datée), sous
  un nom libre (`_2`, `_3`...). Le prompt est bloqué (`decision: block`) : il n'atteint jamais le modèle.
  Le message affiché donne les noms, jamais les valeurs.
- Coffre indisponible : blocage quand même, rien n'est rangé, l'élève est renvoyé vers `/pgvault:setup`.
- Secrets produits par l'agent : redirection directe vers `pgvault put` (skill).
- Aligné sur le coffre d'origine, qui vérifie un jeton auprès du fournisseur avant de l'écrire : option
  `put --verify` (GitHub, OpenAI, Anthropic, Stripe).

## Options écartées

- Remplacer la valeur par son nom et laisser passer le prompt : Claude Code ne permet pas de réécrire un
  prompt depuis ce hook ; seul le blocage garantit que la valeur ne part pas.
- Détection par entropie seule : trop de faux positifs (empreintes, identifiants).

## Résidu local (vérifié en session réelle, 0.3.1)

Claude Code écrit le prompt bloqué dans la transcription locale (`queue-operation`, puis message système
« Original prompt ») après le hook, et peut l'écrire dans `history.jsonl`. Le hook lance un processus
détaché (`pgvault scrub`, valeurs sur l'entrée standard) qui remplace chaque valeur par `[pgvault:<nom>]`
dans ces deux fichiers (passages à 1, 3, 8, 20 et 60 s). Vérifié : 0 occurrence restante, 2 remplacements.
Le message de blocage affiché dans le terminal de l'élève reprend son prompt : c'est son propre écran,
rien ne part au modèle.
