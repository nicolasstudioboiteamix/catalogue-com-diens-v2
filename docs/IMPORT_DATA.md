# 📊 Guide d'Import de Données

## Import depuis Google Sheets

### Étape 1 : Préparer Google Sheets

Votre feuille doit avoir ces colonnes **exactement dans cet ordre** :

| Sexe | Nom | Prénom | Séances dirigées | Type | Téléphone | Email | Joué | Voix enfant | Chant | Catégorie |
|------|-----|--------|------------------|------|-----------|-------|------|-------------|-------|-----------|
| F | MARTIN | Sophie | Oui | Premium | 06 12 34 56 78 | sophie@email.com | Oui | | oui | Joué |
| H | DUPONT | Jean | Oui | Standard | 06 98 76 54 32 | jean@email.com | Non | | | Voix off |

### Format des colonnes :

1. **Sexe** : `F` (Femme) ou `H` (Homme)
2. **Nom** : En MAJUSCULES
3. **Prénom** : Sera formaté automatiquement (première lettre majuscule)
4. **Séances dirigées** : `Oui` ou `Non`
5. **Type** : `Premium` (→ Classement Interne) ou `Standard` (→ Classement Externe) ou vide
6. **Téléphone** : Format libre
7. **Email** : Unique, obligatoire
8. **Joué** : `Oui` si voix jouée
9. **Voix enfant** : `oui` si compétence voix enfant
10. **Chant** : `oui` si compétence chant
11. **Catégorie** : `Joué` ou `Voix off`

### Étape 2 : Exporter en CSV

1. Dans Google Sheets : **Fichier** > **Télécharger** > **Valeurs séparées par des virgules (.csv)**
2. Le fichier CSV est téléchargé

### Étape 3 : Importer dans l'application

1. Se connecter en tant qu'**Admin**
2. Aller dans l'onglet **"Base de données"**
3. Cliquer sur **"📤 Importer CSV"**
4. Sélectionner votre fichier CSV
5. Attendre le traitement (quelques secondes)
6. ✅ Les comédiens sont créés !

## Format CSV Détaillé

### Colonnes obligatoires

1. **Nom** (texte)
   - En MAJUSCULES recommandé
   - Exemple : `DUPONT`, `MARTIN-LEFEBVRE`

2. **Prénom** (texte)
   - Sera automatiquement formaté : première lettre majuscule
   - Exemple : `jean` devient `Jean`, `MARIE` devient `Marie`

3. **Sexe** (texte)
   - Valeurs acceptées : `Homme` ou `Femme`
   - Sensible à la casse

4. **Email** (texte)
   - Doit être unique
   - Format valide requis
   - Si doublon : ligne ignorée

5. **Téléphone** (texte)
   - Format libre
   - Exemple : `0612345678`, `+33 6 12 34 56 78`

6. **Classement** (texte)
   - Valeurs : `interne`, `externe` ou **laisser vide**
   - Autre valeur = pas de classement

7-11. **Compétences** (texte)
   - `oui` = compétence activée ✓
   - `non` ou vide = compétence désactivée ✗
   - Non sensible à la casse

### Exemple complet

```csv
Nom,Prénom,Sexe,Email,Téléphone,Classement,Séances dirigées,Voix off,Voix jouée,Voix enfant,Chant
DUBOIS,Pierre,Homme,pierre.dubois@email.com,0612345678,interne,oui,oui,non,non,non
BERNARD,Marie,Femme,marie.bernard@email.com,0698765432,externe,non,oui,oui,oui,oui
PETIT,Luc,Homme,luc.petit@email.com,0645678901,,oui,non,oui,non,non
DURAND,Julie,Femme,julie.durand@email.com,0656789012,interne,non,oui,oui,non,oui
```

## Règles de Traitement

### Formatage automatique

✅ **Nom complet créé** : `Prénom NOM`
- `jean DUPONT` → `Jean DUPONT`
- `MARIE martin` → `Marie MARTIN`

✅ **Statut par défaut** : Actif

✅ **Classement** :
- `interne` → Badge Interne
- `externe` → Badge Externe
- Vide → Pas de classement

### Gestion des doublons

Si l'**email existe déjà** :
- ❌ Ligne ignorée
- ⚠️ Message dans console
- Compteur de lignes ignorées affiché

### Validation

**Lignes rejetées si** :
- Email manquant ou invalide
- Sexe différent de "Homme" ou "Femme"
- Nom ou Prénom vide

## Cas d'Usage

### Import Initial

Vous avez 50 comédiens dans Excel/Google Sheets :

1. **Préparer** les données au format requis
2. **Exporter** en CSV
3. **Importer** dans l'app
4. **Vérifier** dans Base de données > Filtrer
5. **Corriger** manuellement si nécessaire

### Ajout Groupé

Nouveaux comédiens à ajouter :

1. Créer nouveau fichier CSV avec nouveaux noms
2. Suivre le même format
3. Importer
4. Les existants sont ignorés, nouveaux ajoutés

### Mise à Jour

⚠️ **L'import ne met PAS à jour** les existants

Pour modifier :
1. Exporter la base actuelle
2. Modifier dans Excel
3. Supprimer les comédiens dans l'app
4. Ré-importer le CSV modifié

## Dépannage

### "Aucun comédien importé"

**Causes possibles** :
- Format CSV incorrect
- Colonnes dans le mauvais ordre
- Encodage du fichier (doit être UTF-8)
- Tous les emails existent déjà

**Solution** :
1. Ouvrir CSV dans éditeur texte
2. Vérifier première ligne (en-têtes)
3. Vérifier séparateur `,` (virgule)
4. Tester avec 2 lignes seulement

### "Certains comédiens manquent"

**Causes** :
- Doublons d'email
- Champs obligatoires vides
- Format email invalide

**Solution** :
1. Regarder console navigateur (F12)
2. Noter les emails rejetés
3. Corriger et ré-importer

### "Accents cassés"

**Cause** : Encodage du fichier

**Solution** :
1. Ouvrir CSV dans Notepad++, VS Code, etc.
2. Enregistrer sous... UTF-8 (sans BOM)
3. Ré-importer

### "Classement ne s'affiche pas"

**Vérifier** :
- Colonne "Classement" bien écrite
- Valeur exacte : `interne` ou `externe`
- Pas d'espaces avant/après

## Exemples de Fichiers

### Minimal (3 comédiens)

```csv
Nom,Prénom,Sexe,Email,Téléphone,Classement,Séances dirigées,Voix off,Voix jouée,Voix enfant,Chant
DUPONT,Jean,Homme,jean@test.com,0612345678,interne,oui,oui,non,non,non
MARTIN,Sophie,Femme,sophie@test.com,0698765432,externe,non,oui,oui,non,non
BERNARD,Luc,Homme,luc@test.com,0645678901,,oui,non,non,non,oui
```

### Complet (avec tous types)

```csv
Nom,Prénom,Sexe,Email,Téléphone,Classement,Séances dirigées,Voix off,Voix jouée,Voix enfant,Chant
LEFEBVRE,Pierre,Homme,pierre.lefebvre@test.com,+33 6 12 34 56 78,interne,oui,oui,oui,non,oui
DUBOIS,Marie,Femme,marie.dubois@test.com,06 23 45 67 89,externe,non,oui,oui,oui,non
THOMAS,Julien,Homme,julien.thomas@test.com,0634567890,,oui,oui,non,non,non
ROBERT,Claire,Femme,claire.robert@test.com,0645678901,interne,non,oui,oui,oui,oui
PETIT,Antoine,Homme,antoine.petit@test.com,0656789012,externe,oui,non,oui,non,non
```

## Support

Des questions ? Consultez :
- `ADMIN_GUIDE.md` pour plus de détails
- Console navigateur (F12) pour les erreurs
- Testez avec 2-3 lignes d'abord !
