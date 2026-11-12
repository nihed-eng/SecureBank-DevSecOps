# SecureBank — API de démonstration sécurité (DevSecOps)

API bancaire fictive construite avec **Python 3.12, Flask et SQLite**, servant de support à un projet DevSecOps : sécurité applicative, automatisation CI/CD, SAST, SCA, scan de secrets et sécurité des conteneurs.

> **Aucune donnée bancaire réelle ne doit être utilisée.**
> Le mode normal est le **mode sécurisé**. Un mode de laboratoire local introduit quelques défauts contrôlés pour illustrer les limites des scanners et des tests.

## Sommaire

- [Structure du projet](#structure-du-projet)
- [Installation locale](#installation-locale)
- [Variables d'environnement](#variables-denvironnement)
- [Mode démonstration vulnérable](#mode-démonstration-vulnérable--local-uniquement)
- [Endpoints](#endpoints)
- [Tests et contrôles de sécurité](#tests-et-contrôles-de-sécurité)
- [Docker](#docker)
- [Pipeline CI/CD](#pipeline-cicd)
- [Dépôts GitLab et GitHub](#dépôts-gitlab-et-github)
- [Limites et pistes d'amélioration](#limites-et-pistes-damélioration)
- [Auteur et licence](#auteur-et-licence)

## Structure du projet

```text
SecureBank/
├── src/                  # Code de l'API Flask
├── tests/                # Tests Pytest (fonctionnels et sécurité)
├── ci/                   # Scripts utilisés par le pipeline CI/CD
├── .semgrep/             # Règles Semgrep locales (sans dépendance DNS)
├── monitoring/           # Supervision et suivi du projet
├── reports/              # Rapports de scans de sécurité
├── docs/                 # Documentation du projet
├── .gitlab-ci.yml        # Pipeline GitLab CI/CD
├── .gitleaks.toml        # Configuration Gitleaks
├── .pre-commit-config.yaml  # Hooks pre-commit (black, bandit, secrets)
├── .env.example          # Modèle de variables d'environnement
├── Dockerfile            # Image durcie (utilisateur non-root)
├── requirements.txt      # Dépendances Python
└── README.md
```

## Installation locale

```bash
cd SecureBank
python3.12 -m venv .venv
source .venv/bin/activate       # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

L'API est disponible sur `http://127.0.0.1:5000`. `GET /api/health` vérifie son état. La base `securebank.db` est créée automatiquement.

Pour tout environnement autre que local, définissez une clé aléatoire forte dans `SECRET_KEY` et un chemin de base de données adapté.

## Variables d'environnement

Copiez `.env.example` vers `.env` et renseignez vos propres valeurs. **Ne commitez jamais le fichier `.env`.**

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | Clé de signature des jetons. Doit être aléatoire et forte hors environnement local. |
| `VULNERABLE_DEMO` | `0` (défaut) : mode sécurisé. `1` : mode démo vulnérable, local uniquement. |
| Chemin de la base | Emplacement de la base SQLite (voir `.env.example` pour le nom exact). |

Les secrets du pipeline (jeton Telegram, accès API GitLab, etc.) se configurent dans les **variables CI/CD masquées** de GitLab, jamais dans le dépôt.

## Mode démonstration vulnérable — local uniquement

```bash
VULNERABLE_DEMO=1 python -m flask --app src.app:app run --host 127.0.0.1 --port 5000
```

En mode démo, le code expose à dessein :

- des requêtes SQL formatées par chaîne à l'inscription et à la connexion (injection SQL) ;
- un hash SHA-256 rapide et sans sel ;
- un accès IDOR sur `GET /api/accounts/<id>` ;
- une réponse HTML reflétant le paramètre `name` sur `GET /api/users/demo-profile` (XSS).

> **Avertissement :** ne publiez jamais ce mode, ne le mettez pas dans Docker/CI, ne l'exécutez pas sur un réseau partagé et utilisez uniquement une base jetable. Ces failles sont des démonstrations éducatives, pas une configuration acceptable pour une vraie application.

Dans les **deux modes**, on retrouve : mot de passe de 12 caractères minimum, authentification par jeton signé avec expiration (1 h), gestion des comptes et consultation des transactions.

## Endpoints

| Méthode | Route | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | Non | Disponibilité |
| POST | `/api/auth/register` | Non | Inscription `{username,email,password}` |
| POST | `/api/auth/login` | Non | Connexion ; renvoie un jeton Bearer |
| GET | `/api/users/me` | Oui | Profil courant |
| GET | `/api/users/<id>` | Oui | Profil de soi-même ou ADMIN |
| GET | `/api/users/demo-profile?name=...` | Non | Sink XSS, uniquement en mode démo |
| POST | `/api/accounts` | Oui | Crée un compte `{label}` |
| GET | `/api/accounts` | Oui | Comptes propres ; ADMIN voit tout |
| GET | `/api/accounts/<id>` | Oui | Détail, contrôlé par propriétaire en mode sûr |
| GET | `/api/transactions` | Oui | Transactions des comptes propres |
| GET | `/api/transactions?account_id=<id>` | Oui | Filtre sécurisé par compte |
| GET | `/api/transactions/<id>` | Oui | Détail autorisé |

Exemple :

```bash
curl -s http://127.0.0.1:5000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.test","password":"correct-horse-battery"}'

# Réutiliser le token renvoyé :
curl -H 'Authorization: Bearer <TOKEN>' http://127.0.0.1:5000/api/accounts
```

Aucun endpoint public de création d'ADMIN n'est fourni. Pour les tests, le rôle est contrôlé en base ; ne créez jamais un rôle élevé à partir d'un champ fourni par l'utilisateur.

## Tests et contrôles de sécurité

```bash
pytest -q
pip install bandit semgrep pre-commit
bandit -r src -ll
semgrep scan --config p/python src
pre-commit install && pre-commit run --all-files
gitleaks detect --source . -v
```

| Outil | Type | Ce qu'il apporte | Limite |
|---|---|---|---|
| **Pytest** | Tests | Vérifie le comportement métier, dont le contrôle d'accès (IDOR). | Ne détecte que ce qui est testé. |
| **Bandit** | SAST | Détecte des constructions Python risquées. | Ne prouve pas l'absence de failles. |
| **Semgrep** | SAST | Signale certaines constructions SQL / XSS (règles locales dans `.semgrep/`). | Ne prouve pas l'absence de ces failles. |
| **Gitleaks** | Secrets | Détecte des motifs de secrets dans l'historique Git. | Ne vérifie pas la validité d'un secret. |
| **Trivy** | SCA / image | Détecte les vulnérabilités connues (dépendances, image). | Ne détecte pas toutes les erreurs de configuration ; les résultats évoluent avec le temps. |

Le contrôle d'accès cassé (IDOR) est un défaut de **logique métier** : il est mis en évidence par les tests Pytest, et non garanti par une détection automatique de Semgrep ou Bandit. En mode sécurisé, l'accès à un compte d'un autre utilisateur doit être refusé ; en mode démo, il est volontairement possible.

## Docker

```bash
docker build -t securebank .
docker run --rm -p 127.0.0.1:5000:5000 \
  -e SECRET_KEY='replace-with-random-secret' \
  -v securebank-data:/data securebank
```

Le conteneur tourne en **utilisateur non-root** et fixe `VULNERABLE_DEMO=0`. La persistance SQLite nécessite le volume `/data`.

> N'exposez pas ce prototype publiquement sans durcissement ni déploiement TLS.

## Pipeline CI/CD

Le pipeline officiel est défini dans `.gitlab-ci.yml`. Il enchaîne les contrôles suivants :

1. **Tests** : Pytest.
2. **SAST** : Bandit et Semgrep (règles locales).
3. **Secrets** : Gitleaks.
4. **Build** : construction de l'image Docker.
5. **Scan d'image** : Trivy, avec quality gate sur les vulnérabilités HIGH/CRITICAL.
6. **Rapports** : génération des rapports de sécurité (`reports/`) et envoi d'une notification Telegram.

<!-- À VÉRIFIER : adaptez cette liste à l'ordre réel des stages de .gitlab-ci.yml
     (ajoutez le DAST, par exemple OWASP ZAP, et l'étape de production si elles existent). -->

Le pipeline échoue sur les règles configurées. Adaptez le runner Docker-in-Docker, les politiques de version d'images, les rapports SARIF/JSON et les seuils aux règles de votre organisation. Évitez `latest` en production et épinglez les images CI à des versions ou digests validés.

## Dépôts GitLab et GitHub

- **GitLab** : dépôt de référence, où s'exécute le pipeline CI/CD.
- **GitHub** : miroir public du projet. Le fichier `.gitlab-ci.yml` n'est pas exécuté par GitHub Actions.

## Limites et pistes d'amélioration

Pour une application de production, il faudrait notamment :

- remplacer les jetons de démonstration par une gestion de session avec rotation robuste ;
- ajouter une limitation de débit (rate limiting) ;
- ajouter une protection CSRF si des cookies sont utilisés ;
- mettre en place une journalisation de sécurité, des migrations de base de données et une politique de sauvegarde ;
- réaliser une revue de sécurité complète et un déploiement derrière TLS.

## Auteur et licence

Projet réalisé par **Nihed Mathlouthi** ([@nihed-eng](https://github.com/nihed-eng)) dans un but pédagogique.

Licence : à définir (par exemple MIT, en ajoutant un fichier `LICENSE`).
