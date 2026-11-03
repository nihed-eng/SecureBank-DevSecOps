# Guide du laboratoire sécurité

1. Exécuter uniquement sur `127.0.0.1` avec une base jetable; garder le mode sécurisé par défaut.
2. Lancer Pytest, Bandit, Semgrep et Gitleaks sur le code sécurisé et enregistrer les résultats.
3. Activer `VULNERABLE_DEMO=1` seulement dans un terminal local isolé, avec `securebank.db` supprimée avant le test.
4. Comparer statiquement les résultats. SQLi / hash faible peuvent être repérés par règles ciblées; une détection dépend des règles et de la version. Gitleaks ne prouve pas la présence de tout secret codé en dur; aucun secret réel n’est fourni.
5. Tester le contrôle d’accès avec deux utilisateurs et comparer les réponses `/api/accounts/<id>`; les tests fonctionnels sont la preuve ici.
6. Examiner la réponse HTML de `/api/users/demo-profile?name=...` : la preuve est le contenu reflété; Semgrep n’est pas un navigateur et ne démontre pas l’exploitabilité client.
7. Pour Docker, utiliser seulement l’image en mode sûr. Trivy peut trouver des CVE connues dans les dépendances/image; une configuration Docker nécessite une analyse adaptée et ne sera pas toujours signalée.
8. Revenir au mode sûr, supprimer la base de démo, exécuter les tests et conserver les rapports avant/après dans `reports/`.

| Sujet | Moyen de preuve réaliste | Scanner pertinent | Limite |
|---|---|---|---|
| SQL injection | test de comportement + revue | Semgrep | dépend des règles et du flux |
| XSS réfléchi | réponse HTML + navigateur de labo | Semgrep | pas de preuve de rendu/exploitabilité client |
| hash faible | revue de l’algorithme | Bandit / Semgrep | règles possibles, faux positifs |
| secret codé en dur | motif de secret factice / revue Git | Gitleaks | non exhaustif; ne jamais déposer un vrai secret |
| dépendance vulnérable | SBOM/CVE de version | Trivy | base CVE évolutive |
| accès cassé | tests utilisateur A/B | Pytest | scanners statiques généralement insuffisants |
| Docker risqué | revue Dockerfile / config | Trivy config | couverture dépend de la politique |
