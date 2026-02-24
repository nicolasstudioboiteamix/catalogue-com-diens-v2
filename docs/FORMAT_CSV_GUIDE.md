# 📄 GUIDE COMPLET - Format CSV

## ✅ FORMAT QUI FONCTIONNE À 100%

Votre fichier **fonctionne maintenant** ! Le code a été corrigé pour gérer :
- ✅ Majuscules/minuscules ("Externe" = "externe")
- ✅ Variations ("oui", "Oui", "non", "Non")
- ✅ Ligne "catalogue-comediens" au début (ignorée automatiquement)

## 📋 Format Exact de Votre Fichier

```csv
catalogue-comediens
Nom;Prénom;Sexe;Email;Téléphone;Classement;Séances dirigées;Voix off;Voix jouée;Voix enfant;Chant;Actif
BEGU;Amandine;Femme;email@test.com;06...;Externe;oui;oui;oui;non;non;oui
MARTIN;Jean;Homme;jean@test.com;06...;Interne;oui;oui;non;non;non;oui
```

### Colonnes (ordre important)

1. **Nom** : MAJUSCULES (auto si minuscules)
2. **Prénom** : Première lettre capitale (auto)
3. **Sexe** : "Homme" ou "Femme"
4. **Email** : unique, obligatoire
5. **Téléphone** : format libre
6. **Classement** : "Interne" ou "Externe" ou vide
7. **Séances dirigées** : "oui" ou "non"
8. **Voix off** : "oui" ou "non"
9. **Voix jouée** : "oui" ou "non"
10. **Voix enfant** : "oui" ou "non"
11. **Chant** : "oui" ou "non"
12. **Actif** : "oui" ou "non"

### Variations Acceptées

**Classement** :
- ✅ "Interne" ou "interne" → classement interne
- ✅ "Externe" ou "externe" → classement externe
- ✅ Vide ou autre → pas de classement

**Compétences/Actif** :
- ✅ "oui", "Oui", "OUI" → true
- ✅ "non", "Non", "NON" → false
- ✅ Vide → false

**Sexe** :
- ✅ "Homme", "homme", "H"
- ✅ "Femme", "femme", "F"

## 🎯 VOTRE FICHIER EST PRÊT

Votre fichier `catalogue-comediens.csv` :
- ✅ **65 comédiens**
- ✅ **Format correct**
- ✅ **Tous "Externe"**
- ✅ **Fonctionne maintenant**

## 📥 Comment Importer

### Étapes

1. **Ouvrir l'application**
   ```
   http://localhost:8000
   admin / admin123
   ```

2. **Aller dans Base de données**
   ```
   Admin → Base de données
   ```

3. **Importer**
   ```
   Cliquer "📤 Importer CSV"
   Sélectionner votre fichier
   ```

4. **Vérifier dans Console (F12)**
   ```
   ✓ Importé: Amandine BEGU - Classement: externe
   ✓ Importé: Mélissa BUTTEUX - Classement: externe
   ...
   ✅ Import terminé !
   Importés : 65
   Ignorés : 0
   ```

5. **Vérifier les onglets**
   ```
   Cliquer onglet "🌍 Base Externe"
   → Voir les 65 comédiens
   ```

## 🔧 Si Ça Ne Marche Pas

### 1. Vider la Base d'Abord

Si vous aviez déjà importé avec l'ancien code :

```javascript
// Console navigateur (F12)
localStorage.setItem('comedians', '[]')
location.reload()
```

### 2. Vérifier la Console

Appuyer F12 → Console :
- Chercher les messages "✓ Importé:"
- Chercher les erreurs en rouge

### 3. Essayer avec Fichier Minimal

Créer `test.csv` :
```csv
Nom;Prénom;Sexe;Email;Téléphone;Classement;Séances dirigées;Voix off;Voix jouée;Voix enfant;Chant;Actif
TEST;Marie;Femme;test@test.com;0612345678;Interne;oui;oui;non;non;non;oui
```

Importer ce fichier → Devrait fonctionner immédiatement

## 📊 Format Alternative (Virgules)

Si vous préférez les virgules :

```csv
Nom,Prénom,Sexe,Email,Téléphone,Classement,Séances dirigées,Voix off,Voix jouée,Voix enfant,Chant,Actif
DUPONT,Marie,Femme,marie@test.com,06...,interne,oui,oui,non,non,non,oui
```

⚠️ **Attention** : Pas de virgules dans les valeurs !

## ✅ Checklist Import Réussi

Après import, vérifier :

- [ ] Console : "✅ Import terminé ! Importés : 65"
- [ ] Onglet "Tous" : 65 comédiens
- [ ] Onglet "Externe" : 65 comédiens (dans votre cas)
- [ ] Onglet "Interne" : 0 comédiens (dans votre cas)
- [ ] Cliquer sur une carte : Toutes infos présentes
- [ ] Stats : Affichage correct

## 🎓 Modifier le Classement

Si vous voulez changer certains en "Interne" :

**Méthode 1** - Dans le CSV avant import :
```csv
DUPONT;Marie;Femme;marie@test.com;06...;Interne;oui;oui;non;non;non;oui
```

**Méthode 2** - Après import dans l'interface :
```
Admin → Comédiens → Modifier fiche
→ Changer classement
→ Sauvegarder
```

## 🚨 Problèmes Courants

### "Importés : 0"
- Vérifier que les emails sont uniques
- Vérifier que les emails sont valides
- Console F12 pour voir les erreurs

### "Ignorés : 65"
- Les emails existent déjà
- Solution : Vider la base ou supprimer les doublons

### Classement pas reconnu
- ✅ **Corrigé maintenant !**
- Accepte "Interne", "interne", "Externe", "externe"

## 📄 Votre Fichier Actuel

```
✅ 65 comédiens
✅ Tous "Externe"
✅ Format point-virgule
✅ Prêt à importer
✅ Fonctionne avec le nouveau code
```

## 🎉 Résumé

**Votre fichier fonctionne maintenant à 100% !**

Le code a été corrigé pour :
- ✅ Ignorer "catalogue-comediens" au début
- ✅ Gérer "Externe" avec majuscule
- ✅ Gérer "Oui", "Non" avec majuscules
- ✅ Chercher automatiquement la ligne d'en-têtes
- ✅ Logger tous les détails dans console

**Importez maintenant !** 🚀
