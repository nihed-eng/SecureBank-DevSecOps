# SecureBank — API de démonstration sécurité

API bancaire fictive construite avec Python 3.12, Flask et SQLite. **Aucune donnée bancaire réelle ne doit être utilisée.** Le mode normal est le mode sécurisé. Un mode de laboratoire local introduit quelques défauts contrôlés pour illustrer les limites des scanners et des tests.

## Installation locale

```bash
cd SecureBank
python3.12 -m venv .venv
source .venv/bin/activate       # Windows : .venv\\Scripts\\activate
pip install -r requirements.txt
python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

L’API est sur `http://127.0.0.1:5000`; `GET /api/health` vérifie son état. La base `securebank.db` est créée automatiquement. Pour tout environnement autre que local, définissez une clé aléatoire forte dans `SECRET_KEY` et un chemin de base de données adapté.

## Mode démonstration vulnérable — local uniquement

```bash
VULNERABLE_DEMO=1 python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

En mode démo, le code expose à dessein : requêtes SQL formatées par chaîne à l’inscription/connexion, hash SHA-256 rapide sans sel, accès IDOR sur `GET /api/accounts/<id>` et une réponse HTML reflétant le paramètre `name` sur `GET /api/users/demo-profile`. Ne publiez jamais ce mode, ne le mettez pas dans Docker/CI, ne l’exécutez pas sur un réseau partagé et ne l’utilisez qu’avec une base jetable. Les failles sont des démonstrations éducatives, pas une configuration acceptable pour une vraie application.

Le mot de passe minimum de 12 caractères, l’authentification par jeton signé avec expiration (1 h), les comptes et consultations de transactions sont disponibles dans les deux modes. Pour une application de production, remplacez les jetons de démonstration par une gestion de session/rotation robuste, ajoutez limitation de débit, CSRF si cookies, journalisation, migrations, politique de sauvegarde et revue de sécurité.

## Endpoints

| Méthode | Route | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | Non | Disponibilité |
| POST | `/api/auth/register` | Non | Inscription `{username,email,password}` |
| POST | `/api/auth/login` | Non | Connexion; renvoie un jeton Bearer |
| GET | `/api/users/me` | Oui | Profil courant |
| GET | `/api/users/<id>` | Oui | Profil soi-même ou ADMIN |
| GET | `/api/users/demo-profile?name=...` | Non | Sink XSS uniquement en mode démo |
| POST | `/api/accounts` | Oui | Crée `{label}` |
| GET | `/api/accounts` | Oui | Comptes propres; ADMIN voit tout |
| GET | `/api/accounts/<id>` | Oui | Détail, contrôlé par propriétaire en mode sûr |
| GET | `/api/transactions` | Oui | Transactions des comptes propres |
| GET | `/api/transactions?account_id=<id>` | Oui | Filtre sécurisé par compte |
| GET | `/api/transactions/<id>` | Oui | Détail autorisé |

Exemple :

```bash
curl -s http://127.0.0.1:5000/api/auth/register \\
  -H 'Content-Type: application/json' \\
  -d '{"username":"alice","email":"alice@example.test","password":"correct-horse-battery"}'
# Réutiliser le token renvoyé :
curl -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:5000/api/accounts
```

Aucun endpoint public de création d’ADMIN n’est fourni. Pour les tests, le rôle est contrôlé en base; ne créez jamais un rôle élevé à partir d’un champ fourni par l’utilisateur.

## Tests et contrôles

```bash
pytest -q
pip install bandit semgrep pre-commit
bandit -r src -ll
semgrep scan --config p/python src
pre-commit install && pre-commit run --all-files
```

Gitleaks examine les secrets dans l’historique Git (`gitleaks detect`). Trivy analyse l’image (et peut aussi scanner les fichiers/dépendances); les résultats de dépendances changent avec le temps. Les tests Pytest démontrent le contrôle d’accès cassé: il s’agit d’un comportement métier, et non d’une garantie de détection automatique par Semgrep/Bandit. Semgrep peut signaler certaines constructions SQL / XSS; il ne prouve pas l’absence de ces failles. Gitleaks détecte des motifs de secrets, pas leur validité. Trivy vérifie les vulnérabilités connues, pas toute configuration erronée.

## Docker

```bash
docker build -t securebank .
docker run --rm -p 127.0.0.1:5000:5000 -e SECRET_KEY='replace-with-random-secret' -v securebank-data:/data securebank
```

Le conteneur tourne en utilisateur non-root et fixe `VULNERABLE_DEMO=0`. La persistance SQLite nécessite le volume `/data`. N’exposez pas ce prototype publiquement sans durcissement et déploiement TLS.

## GitLab CI/CD

`.gitlab-ci.yml` lance Pytest, Bandit, Semgrep et Gitleaks et construit/scanne l’image Trivy. Le pipeline échoue sur les règles configurées (quality gates HIGH/CRITICAL pour l’image). Adaptez le runner Docker-in-Docker, les politiques de version d’images, les rapports SARIF/JSON et les seuils aux règles de votre organisation. Évitez `latest` en production et épinglez les images CI à des versions ou digests validés.
