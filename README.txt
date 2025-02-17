# Projet ANSSI Alertes et CVE

Ce projet a été conçu pour traiter les flux RSS d'alertes et d'avis publiés par l'ANSSI, enrichir les données associées à ces bulletins avec des informations détaillées sur les CVE, et consolider ces données dans un fichier exploitable.

## Fonctionnalités principales

1. Extraction des flux RSS:
   - Collecte les flux RSS des avis et alertes publiés par l'ANSSI.
   - Identifie les nouvelles entrées qui n'ont pas encore été traitées.

2. Extraction des informations CVE:
   - Télécharge les détails des CVE associés à chaque bulletin via des APIs externes (MITRE et EPSS).
   - Enrichit les bulletins avec des informations critiques telles que les scores CVSS, les types CWE, et les probabilités d'exploitation (EPSS).

3. Consolidation des données:
   - Compile les informations extraites dans un fichier CSV pour une analyse ultérieure.

4. Notifications par email:
   - Envoie des notifications personnalisées aux destinataires en fonction des mots-clés associés aux bulletins.

## Prérequis

- Python 3.7 ou supérieur.

- Les modules suivants doivent être installés :

  bash:
  pip install feedparser python-dotenv pandas requests
  
- Créez un fichier `.env` contenant les informations de configuration pour l'envoi des emails :
  
  EMAIL_USER=votre_adresse_email@example.com
  EMAIL_PASSWORD=votre_mot_de_passe
  SMTP_SERVER=smtp.votre_serveur_email.com
  SMTP_PORT=587
  

## Installation et Utilisation

1. Préparez votre environnement :
   - Placez tous les fichiers nécessaires dans le même répertoire : `Main.py`, `Classes.py`, et le fichier `.env`.

2. **Exécutez le script principal** :
   - Ouvrez un terminal et accédez au répertoire contenant vos fichiers.
   - Lancez le script avec Python :
     bash
     python Main.py
     

3. Résultats attendus:
   - Les nouvelles données consolidées seront enregistrées dans un fichier CSV nommé `DataframeConsolider.csv`. Et les nouvelles URL dans le fichier `processed_urls.txt`. Si les fichiers ne sont pas déjà présent il seront créé lors de l'exécution du script.
   - Les notifications pertinentes seront envoyées aux destinataires configurés.

## Structure du projet
- `Main.py` : Point d'entrée principal du projet.
- `Classes.py` : Définitions des classes `CERT` et `CVE` utilisées dans le traitement des données.
- `DataframeConsolider.csv` : Fichier de sortie contenant les données consolidées.
- `.env` : Fichier de configuration contenant les variables d'environnement pour l'envoi des emails.



