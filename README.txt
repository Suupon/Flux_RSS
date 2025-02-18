# 🛡️ Projet ANSSI Alertes et CVE

Ce projet a été conçu pour traiter les flux RSS d'alertes et d'avis publiés par l'ANSSI, enrichir les données associées à ces bulletins avec des informations détaillées sur les CVE, et consolider ces données dans un fichier exploitable.

---

## 🚀 Fonctionnalités principales

1. ✅ **Extraction des flux RSS** :
   - Collecte les flux RSS des avis et alertes publiés par l'ANSSI.
   - Identifie les nouvelles entrées qui n'ont pas encore été traitées.

2. ✅ **Extraction des informations CVE** :
   - Récupère les détails des CVE associés à chaque bulletin via des APIs externes (MITRE et EPSS).
   - Enrichit les bulletins avec des informations critiques telles que les scores CVSS, les types CWE et les probabilités d'exploitation (EPSS).

3. ✅ **Consolidation des données** :
   - Compile les informations extraites dans un fichier CSV pour une analyse ultérieure.

4. ✅ **Notifications par email** :
   - Envoie des notifications personnalisées aux destinataires en fonction des mots-clés associés aux bulletins.

---

## 🛠️ Prérequis

- **Python 3.7 ou supérieur**
- **Modules Python requis** :
  ```bash
  pip install feedparser python-dotenv pandas requests
  ```
- **Configuration des emails** : Créez un fichier `.env` contenant les informations suivantes :
  ```env
  EMAIL_USER=votre_adresse_email@example.com
  EMAIL_PASSWORD=votre_mot_de_passe
  SMTP_SERVER=smtp.votre_serveur_email.com
  SMTP_PORT=587
  ```

---

## 📚 Installation et Utilisation

1. **Préparez votre environnement** :
   - Placez tous les fichiers nécessaires dans le même répertoire : `Main.py`, `Classes.py`, et `.env`.

2. **Exécutez le script principal** :
   - Ouvrez un terminal et accédez au répertoire contenant vos fichiers.
   - Lancez le script avec Python :
     ```bash
     python Main.py
     ```

3. **Résultats attendus** :
   - Les nouvelles données consolidées seront enregistrées dans `DataframeConsolider.csv`.
   - Les nouvelles URL traitées seront stockées dans `processed_urls.txt`.
   - Si ces fichiers n'existent pas, ils seront créés automatiquement lors de l'exécution du script.
   - Les notifications pertinentes seront envoyées aux destinataires configurés.

---

## 🌐 Structure du projet
- `Main.py` : Point d'entrée principal du projet.
- `Classes.py` : Définitions des classes `CERT` et `CVE` utilisées pour le traitement des données.
- `DataframeConsolider.csv` : Fichier contenant les données consolidées.
- `processed_urls.txt` : Fichier enregistrant les URL déjà traitées.
- `.env` : Fichier de configuration contenant les variables d'environnement pour l'envoi des emails.

---

## 👨‍💻 Auteur
- **Aymen** - [Ton GitHub](https://github.com/Suupon)

---


