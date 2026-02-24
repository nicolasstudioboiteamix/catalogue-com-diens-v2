# Catalogue Comédiens

Application web de gestion et de catalogage de comédiens pour studios d'enregistrement.

## Architecture

```
Navigateur ──HTTPS──► Supabase Edge Function (Deno)
                           │  valide session token
                           │  vérifie le rôle (admin/studio/…)
                           ▼
                       Supabase DB (service_role)
                       RLS : accès anon = 0 sur toutes les tables
```

**Niveau de sécurité 3** — aucune clé d'API dans le code client.

---

## Installation

### Prérequis

- Compte [Supabase](https://supabase.com) (plan Free suffisant)
- [Supabase CLI](https://supabase.com/docs/guides/cli) installé
- Hébergement statique (Vercel, Netlify, GitHub Pages…)

### Étape 1 — Base de données

Dans **Supabase Dashboard > SQL Editor**, exécutez dans l'ordre :

1. `supabase/migration-level3.sql`

Ce script crée toutes les tables, active RLS et crée la table de sessions.

### Étape 2 — Configurer `js/config.js`

Remplacez `VOTRE_PROJECT_REF` par la référence de votre projet Supabase
(Dashboard > Project Settings > General > **Reference ID**) :

```js
const SUPABASE_CONFIG = {
    EDGE_URL: 'https://VOTRE_PROJECT_REF.supabase.co/functions/v1/api'
};
```

### Étape 3 — Déployer l'Edge Function

```bash
supabase login
supabase link --project-ref VOTRE_PROJECT_REF
supabase functions deploy api --no-verify-jwt
```

### Étape 4 — Déployer le frontend

Déployez le dossier racine sur votre hébergeur statique.  
GitHub Pages : pousser sur `main`, activer Pages depuis les Settings.

### Étape 5 — Premier accès

Identifiants par défaut (à changer immédiatement) :

| Champ | Valeur |
|---|---|
| Identifiant | `admin` |
| Mot de passe | `admin123` |

---

## Déploiement continu (CI/CD)

Le workflow `.github/workflows/deploy.yml` gère automatiquement :

1. **Injection de la version de build** dans `index.html` (cache-busting automatique)
2. **Déploiement de l'Edge Function** Supabase

### Secrets GitHub requis

Dans **Settings > Secrets and variables > Actions** du dépôt, créez :

| Secret | Valeur |
|---|---|
| `SUPABASE_ACCESS_TOKEN` | Dashboard Supabase > Account > **Access Tokens** |
| `SUPABASE_PROJECT_REF` | Dashboard Supabase > Project Settings > **Reference ID** |

---

## Structure du projet

```
├── index.html                        # Application SPA
├── js/
│   ├── config.js                     # URL Edge Function (pas de clé)
│   ├── supabase-client.js            # Couche données via Edge Function
│   ├── database.js                   # Opérations import/export CSV
│   └── app.js                        # Logique UI
├── css/
│   ├── styles.css
│   └── variables.css
├── supabase/
│   ├── functions/api/index.ts        # Edge Function (point d'accès unique DB)
│   └── migration-level3.sql          # Schéma + RLS
├── docs/
│   ├── FORMAT_CSV_GUIDE.md
│   └── IMPORT_DATA.md
└── .github/workflows/deploy.yml      # CI/CD
```

---

## Rôles utilisateurs

| Rôle | Accès |
|---|---|
| `admin` | Accès complet — gestion utilisateurs, paramètres, imports |
| `studio` | Catalogue complet, uploads audio/photo, absences |
| `manager` | Catalogue + absences (pas de suppression) |
| `comedian` | Son propre profil uniquement |
| `client` | Vue catalogue filtrée, sélection de comédiens |

---

## Sécurité

- **Aucune clé Supabase** dans le code client ou dans Git
- Toutes les requêtes DB passent par l'Edge Function (Deno, `service_role`)
- RLS Supabase : `anon` = aucun accès sur toutes les tables
- Sessions avec tokens opaques (32 octets, 8h d'expiration)
- Mots de passe hashés SHA-256 côté serveur
- Cache-busting automatique à chaque déploiement

---

## Import de données

Voir `docs/FORMAT_CSV_GUIDE.md` et `docs/IMPORT_DATA.md`.  
Un fichier CSV d'exemple est disponible dans `docs/catalogue-comediens.csv`.
