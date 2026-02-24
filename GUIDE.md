# Guide d'utilisation — Catalogue Comédiens

## Table des matières
1. [Connexion et sécurité](#connexion)
2. [Rôles et permissions](#rôles)
3. [Administrateur](#admin)
4. [Équipe Studio / Manager](#studio)
5. [Comédien](#comedian)
6. [Client](#client)
7. [Fonctions importantes](#fonctions)
8. [Gestion des identifiants](#identifiants)
9. [Realtime et synchronisation](#realtime)

---

## 1. Connexion et sécurité

- Chaque visite requiert une saisie des identifiants — aucune session n'est conservée entre les onglets.
- Après 8 heures d'activité, la session expire automatiquement.
- Les mots de passe sont hachés en SHA-256 avant stockage — ils ne sont jamais lisibles.
- Toutes les données transitent uniquement via l'Edge Function sécurisée — le navigateur ne possède aucune clé de base de données.

---

## 2. Rôles et permissions

| Action | Admin | Studio | Manager | Comédien | Client |
|--------|:-----:|:------:|:-------:|:--------:|:------:|
| Voir le catalogue complet | ✅ | ✅ | ✅ | — | — |
| Filtrer / rechercher | ✅ | ✅ | ✅ | — | ✅ |
| Voir fiches comédiens | ✅ | ✅ | ✅ | Sa fiche | Sélection |
| Modifier fiches | ✅ | ✅ | ✅ | — | — |
| Uploader audio / photo | ✅ | ✅ | ✅ | — | — |
| Normaliser audio | ✅ | ✅ | ✅ | — | — |
| Gérer les absences | ✅ | ✅ | ✅ | — | — |
| Créer / modifier utilisateurs | ✅ | — | — | — | — |
| Importer CSV / JSON | ✅ | — | — | — | — |
| Voir historique | ✅ | — | — | — | — |
| Modifier paramètres | ✅ | — | — | — | — |
| Envoyer identifiants | ✅ | — | — | — | — |
| Créer liens partagés | ✅ | ✅ | ✅ | — | — |
| Voir sa propre fiche | — | — | — | ✅ | — |
| Sélectionner des comédiens | — | — | — | — | ✅ |

---

## 3. Administrateur

L'administrateur a accès à toutes les fonctions de l'application.

### Navigation
L'admin dispose de 6 onglets :
- **Utilisateurs** — Gérer les comptes de connexion
- **Comédiens** — Voir et modifier les fiches
- **Base de données** — Import/export, statistiques
- **Absences** — Vue calendaire des indisponibilités
- **Historique** — Journal de toutes les actions
- **Paramètres** — Nom du studio, logo

### Aperçu par rôle
Dans la barre de navigation admin, des boutons permettent de simuler la vue d'un autre rôle sans se déconnecter :
- `🎙️ Studio` / `📋 Manager` / `🎭 Comédien` / `👤 Client`
- Une barre orange indique qu'on est en mode aperçu
- Cliquer **✖ Retour admin** pour revenir à la vue normale

### Gestion des utilisateurs
- **Créer un utilisateur** : bouton `+ Créer un utilisateur`
- **Modifier** : cliquer sur l'icône crayon ✏️ à côté d'un utilisateur
- **Désactiver** : cliquer sur 🔄 pour bloquer l'accès sans supprimer le compte
- **Supprimer** : cliquer sur 🗑️ (irréversible)
- **Envoyer identifiants** : cliquer sur 📧 — ouvre le client mail avec les identifiants. Le mot de passe n'est jamais régénéré automatiquement ; seul l'admin peut en définir un nouveau via "Modifier".

### Paramètres studio
- **Nom du studio** : affiché dans les emails et l'interface
- **Logo** : upload d'une image — s'affiche en haut de toutes les vues

---

## 4. Équipe Studio / Manager

### Accès
- Catalogue complet avec tous les filtres
- Modification des fiches comédiens
- Gestion des absences
- Upload audio et photos
- Normalisation audio

### Filtres disponibles
- Sexe, classement (Interne / Externe)
- Compétences (Voix off, Voix jouée, Chant, etc.)
- Timbre (Grave, Médium, Aigu)
- Style (Dynamique, Posé, Naturel, Institutionnel)
- Statut (Actif / Inactif)

### Créer un lien de sélection partagé
1. Sélectionner des comédiens avec les cases à cocher
2. Cliquer sur **📤 Partager la sélection**
3. Copier le lien généré et l'envoyer au client
4. Le client peut accéder à cette sélection sans compte

---

## 5. Comédien

### Accès
Le comédien voit uniquement sa propre fiche après connexion.

### Contenu de la fiche
- Photo de profil
- Informations (nom, sexe, classement)
- Compétences et caractéristiques vocales
- Présentation personnelle
- Extraits audio disponibles

### Gestion des absences
Le comédien peut consulter ses absences mais ne peut pas les modifier directement — cela relève du Studio ou du Manager.

---

## 6. Client

### Accès
Le client voit uniquement les comédiens qui lui ont été partagés par le Studio.

### Sélection
- Le client peut sélectionner jusqu'à 3 comédiens via les cases à cocher
- Les sélections sont visibles par le Studio

---

## 7. Fonctions importantes

### Normalisation audio
Disponible lors de l'upload d'un fichier audio (Studio, Manager, Admin).

**Comment l'utiliser :**
1. Cliquer sur `🔊 Uploader` pour un type d'audio (Présentation, Démo, Promo, etc.)
2. Sélectionner le fichier audio depuis votre ordinateur
3. Cocher `🎚️ Normaliser le volume (-14 LUFS)` avant de valider
4. Le système applique une normalisation automatique pour uniformiser le niveau sonore

**Pourquoi normaliser :** garantit que tous les extraits sonores ont le même niveau d'écoute, évitant les fortes variations de volume entre comédiens.

### Import CSV
1. Admin → Onglet **Base de données** → `📥 Importer CSV`
2. Le fichier doit suivre le format décrit dans `docs/FORMAT_CSV_GUIDE.md`
3. Les doublons (même email) sont ignorés automatiquement
4. Les identifiants de connexion sont créés automatiquement et affichés à la fin de l'import

### Import JSON
Même principe que le CSV mais avec le format JSON exporté par l'application.

### Export
- **CSV** : format tabulaire, compatible Excel
- **JSON** : format complet pour sauvegarde ou migration

### Suppression de la base
Disponible uniquement pour l'admin. Un backup JSON est automatiquement téléchargé avant suppression.

---

## 8. Gestion des identifiants

### Règle fondamentale
Le mot de passe d'un compte ne change **jamais automatiquement**. Il ne change que lorsque l'admin :
1. Modifie manuellement le mot de passe via ✏️ Modifier
2. Clique sur 📧 Envoyer identifiants pour la **première fois** sur un compte sans mot de passe

### Envoyer les identifiants (première fois)
1. Le système génère un mot de passe sécurisé aléatoire
2. Ouvre le client mail avec les identifiants pré-remplis
3. Le mot de passe est affiché une seule fois — **notez-le immédiatement**
4. Après rechargement de la page, le mot de passe en clair n'est plus récupérable

### Renvoyer les identifiants (compte existant)
Le compte a déjà un mot de passe — le renvoyer directement n'est possible que si la page n'a pas été rechargée depuis sa création.

**Si la page a été rechargée :**
1. Admin → ✏️ Modifier l'utilisateur
2. Saisir un nouveau mot de passe
3. Enregistrer
4. Cliquer 📧 Envoyer identifiants (dans la même session, sans recharger)

---

## 9. Realtime et synchronisation

L'application utilise **Supabase Realtime** pour propager les modifications en temps réel à tous les utilisateurs connectés.

### Comment ça fonctionne
- Dès qu'une donnée est modifiée (comédien, utilisateur, absence), tous les navigateurs connectés reçoivent automatiquement la mise à jour.
- Aucun rechargement manuel n'est nécessaire.

### Configuration requise
Pour activer le Realtime, l'administrateur technique doit ajouter la clé `ANON_KEY` de Supabase dans le fichier `js/config.js`.

**Où trouver la clé anon :**
Supabase Dashboard → Project Settings → API → `anon public`

**Important :** la clé anon est conçue pour être publique — elle ne donne aucun accès aux données grâce aux politiques RLS. Elle sert uniquement à recevoir des notifications de changement.

Si la clé n'est pas configurée, les données se rechargent uniquement lors d'actions manuelles (navigation entre onglets, etc.).

---

*Guide version 6 — Catalogue Comédiens*
