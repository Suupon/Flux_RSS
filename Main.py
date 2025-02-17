# -*- coding: utf-8 -*-

import feedparser
import time
from Classes import CERT
from Classes import CVE
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
import requests
import pandas as pd
import re
from email.utils import formataddr



# Méthodes pour l'envoi des mails
def send_email(to_emails, subject, body):
    """
    Envoie un email aux destinataires spécifiés avec un sujet et un corps de message donnés.

    Args:
        to_emails (list): Liste des adresses email des destinataires.
        subject (str): Sujet de l'email.
        body (str): Contenu de l'email.
    """
    load_dotenv(override=True)
    email_user = os.getenv("EMAIL_USER")
    email_password = os.getenv("EMAIL_PASSWORD")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))

    msg = MIMEText(body)
    msg['From'] = formataddr(("ANSSI Notifications", email_user))
    msg['Subject'] = subject
    msg['To'] = "Undisclosed Recipients"

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_user, email_password)
        server.sendmail(email_user, to_emails, msg.as_string())
        server.quit()
        print("Emails envoyés avec succès")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")


def write_email(genre, titre, date, description, cve_list, lien):
    """
    Rédige et envoie un email pour notifier les destinataires d'un bulletin ANSSI.

    Args:
        genre (str): Type de bulletin ("Alerte" ou "Avis").
        titre (str): Titre du bulletin.
        date (str): Date de publication du bulletin.
        description (str): Description du bulletin.
        cve_list (list): Liste des identifiants CVE associés au bulletin.
        lien (str): Lien vers le bulletin complet.
    """
    key_words = ["Linux", "Apache", "Chrome", "Edge", "Mozilla"]
    if genre == "Alerte":
        subject = "Nouvelle Alerte ANSII détectée"
    else:
        subject = "Nouvel Avis ANSII détecté"

    email_lists = {
        "Linux": ["cvepython@gmail.com"],
        "Apache": ["cvepython@gmail.com"],
        "Chrome": ["cvepython@gmail.com"],
        "Edge": ["cvepython@gmail.com"],
        "Mozilla": ["cvepython@gmail.com"]
    }

    for mot in key_words:
        if mot in description or mot in titre:
            destinataire = email_lists.get(mot, [])
            body = (f"Un bulletin susceptible de vous intéresser à été émis !\n\n"
                    f"Titre Bulletin : {titre}\n"
                    f"Date: {date}\n"
                    f"Produit impacté : {mot}\n"
                    f"Description: {description}\n"
                    f"Liste des CVE: {cve_list}\n"
                    f"Consultez les détails ici : {lien}")

            send_email(destinataire, subject, body)


# Méthodes d'historisation des liens utilisés
def load_processed_urls(file_path):
    """
    Charge les URLs déjà traitées à partir d'un fichier.

    Args:
        file_path (str): Chemin du fichier contenant les URLs traitées.

    Returns:
        set: Ensemble des URLs déjà traitées.
    """
    if not os.path.exists(file_path):
        return set()
    with open(file_path, "r") as file:
        return set(line.strip() for line in file)


def save_processed_urls(file_path, urls):
    """
    Sauvegarde les nouvelles URLs traitées dans un fichier.

    Args:
        file_path (str): Chemin du fichier pour sauvegarder les URLs.
        urls (list): Liste des URLs à sauvegarder.
    """
    with open(file_path, "a") as file:
        for url in urls:
            file.write(f"{url}\n")


def extract_rss_feeds(url):
    """
    Extrait les entrées RSS depuis une URL donnée.

    Args:
        url (str): URL du flux RSS.

    Returns:
        list: Liste des entrées extraites du flux RSS.
    """
    try:
        feed = feedparser.parse(url)
        if feed.bozo:
            raise ValueError(f"Erreur lors du parsing du flux RSS: {url}")
        return feed.entries
    except Exception as e:
        print(f"Erreur lors de l'extraction du flux RSS: {url} - {e}")
        return []


def process_rss_entries():
    """
    Traite les flux RSS pour extraire les bulletins et les nouvelles URLs.

    Returns:
        list: Liste des objets CERT représentant les bulletins.
        list: Liste des nouvelles URLs non encore traitées.
    """
    url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
    url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"
    history_file = "processed_urls.txt"

    rss_feed_avis_entries = extract_rss_feeds(url_avis)
    rss_feed_alerte_entries = extract_rss_feeds(url_alerte)
    rss_entries = rss_feed_avis_entries + rss_feed_alerte_entries
    processed_urls = load_processed_urls(history_file)

    bulletins = []
    new_urls = []

    for entry in rss_entries:
        if entry.link not in processed_urls:
            try:
                title = entry.title
                link = entry.link
                description = entry.get("description", "No description available")
                published_date = time.strftime("%Y-%m-%d", entry.published_parsed)

                cert = CERT(title, link, description, published_date)
                bulletins.append(cert)
                new_urls.append(link)
            except AttributeError as e:
                print(f"Erreur lors de la création d'un objet CERT pour l'entrée : {entry} - {e}")
            except Exception as e:
                print(f"Erreur inattendue : {e}")

    print(f"Nombre total de nouveaux bulletins extraits et traités : {len(bulletins)}")
    return bulletins, new_urls


def extract_cve_info(bulletins):
    """
    Extrait les informations CVE pour chaque bulletin et enrichit les objets CERT.

    Args:
        bulletins (list): Liste des objets CERT représentant les bulletins.

    Returns:
        list: Liste mise à jour des bulletins avec les informations CVE extraites.
    """
    for bulletin in bulletins:
        url_2 = bulletin.get_lien() + "json"

        if url_2[46:49] == "AVI":
            bulletin.set_type("Avis")
        elif url_2[48:51] == "ALE":
            bulletin.set_type("Alerte")
        else:
            continue

        response = requests.get(url_2)

        if response.status_code != 200:
            print(f"Erreur lors de la récupération des données pour l'URL: {url_2}")
            continue

        try:
            data = response.json()
        except ValueError:
            print(f"Réponse JSON invalide pour l'URL: {url_2}")
            continue

        ref_cves = list(data.get("cves", []))

        write_email(bulletin.get_type(), 
                    bulletin.get_titre(), 
                    bulletin.get_date(), 
                    bulletin.get_description(), 
                    ref_cves,
                    bulletin.get_lien())

        for cve_entry in ref_cves:
            name = cve_entry.get('name')
            url = cve_entry.get('url')
            if name and url:
                cve = CVE(name, url)
                bulletin.CVE.append(cve)
            else:
                print(f"Entrée CVE invalide: {cve_entry}")

    print("Étape 2 : Extraction des CVE terminée.")
    return bulletins


def dataframe_consolidation(bulletins, output_file="DataframeConsolider.csv"):
    """
    Traite les informations CVE pour chaque bulletin et consolide les données dans un DataFrame.

    Args:
        bulletins (list): Liste des objets CERT représentant les bulletins.
        output_file (str): Chemin du fichier de sortie pour sauvegarder les données consolidées.

    Returns:
        pd.DataFrame: DataFrame contenant les données consolidées.
    """
    
    df = pd.DataFrame()

    for i, cert in enumerate(bulletins, start=1):
        print("Bulletin :", i)

        for index, cve in enumerate(cert.CVE):
            print("CVE:", index + 1)
            cve_id = cve.get_nom()
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response = requests.get(url)

            try:
                data = response.json()
            except ValueError:
                print(f"Erreur JSON pour le CVE {cve_id}")
                continue

            if "error" in data.keys():
                df = pd.concat([df, pd.DataFrame({
                    'Titre Bulletin': [cert.get_titre()],
                    "Lien Bulletin": [cert.get_lien()],
                    "Type Bulletin": [cert.get_type()],
                    'Date': [cert.get_date()],
                    'CVE': [cve_id],
                    'Lien CVE': [url],
                    'Cvss_score': ["N/A"],
                    'Gravite': ["N/A"],
                    'Epss_score': ["N/A"],
                    'CWE': ["N/A"],
                    'Vendor': ["N/A"],
                    'Name': ["N/A"],
                    "Description": [data["error"]]
                })], ignore_index=True)
                continue
            elif data["cveMetadata"]["state"] == "REJECTED":
                df = pd.concat([df, pd.DataFrame({
                                   'Titre Bulletin':[cert.get_titre()],
                                   "Lien Bulletin":[cert.get_lien()],
                                   "Type Bulletin":[cert.get_type()],
                                   'Date':[cert.get_date()],
                                 'CVE':[cve_id],
                                 'Lien CVE':[url],
                                 'Cvss_score': ["N/A"],
                                 'Gravite':["N/A"],
                                 'Epss_score':["N/A"],
                                 'CWE':["N/A"],
                                 'Vendor': ["N/A"], 
                                 'Name': ["N/A"],
                                  "Description":[data["containers"]["cna"]["rejectedReasons"][0]["value"]]})], ignore_index=True)
                continue

            description = data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "Description indisponible")
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [{}])
            cvss_pattern = r"cvssV\\d+(_\\d+)?"
            cvss_score = 'N/A'
            for metric in metrics:
                for key in metric.keys():
                    if re.match(cvss_pattern, key):
                        cvss_score = metric[key].get("baseScore", "N/A")
                        break

            gravite = "Inconnue" if cvss_score == "N/A" else "Critique" if float(cvss_score) > 8 else "Élevée" if float(cvss_score) > 6 else "Moyenne" if float(cvss_score) > 3 else "Faible"


             # Gestion des CWE
            problemtype = data.get("containers", {}).get("cna", {}).get("problemTypes", [{}])
            cwe = problemtype[0].get("descriptions", [{}])[0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0].get("descriptions", [{}])[0].get("description", "Non disponible")

        # Gestion des produits affectés
            affected = data.get("containers", {}).get("cna", {}).get("affected", [])
            for product in affected:
                vendor = product.get("vendor", "Vendeur Inconnu")
                product_name = product.get("product", "Produit Inconnu")

            epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response_epss = requests.get(epss_url)
            epss_data = response_epss.json().get("data", [])
            epss_score = round(float(epss_data[0]["epss"]), 5) if epss_data else "N/A"

            # Ajout des données consolidées au DataFrame
            df = pd.concat([df, pd.DataFrame({
                    'Titre Bulletin': [cert.get_titre()],
                    "Lien Bulletin": [cert.get_lien()],
                    "Type Bulletin": [cert.get_type()],
                    'Date': [cert.get_date()],
                    'CVE': [cve_id],
                    'Lien CVE': [url],
                    'Cvss_score': [cvss_score],
                    'Gravite': [gravite],
                    'Epss_score': [epss_score],
                    'CWE': [cwe],
                    'Description CWE':[cwe_desc],
                    'Vendor': [vendor],
                    'Name': [product_name],
                    "Description": [description]
                })], ignore_index=True)

         # Sauvegarde du DataFrame dans un fichier CSV
    file_exists = os.path.exists(output_file)
    df.to_csv(output_file, mode='a', header=not file_exists, index=False)
    
    if not file_exists:
        print(f"Le fichier {output_file} a été créé avec les colonnes.")
    else:
        print(f"Les nouvelles données ont été ajoutées au fichier {output_file}.")
    




start_time = time.time()
    # Étape 1 : Traitement des flux RSS
bulletins, new_urls = process_rss_entries()
    
    # Étape 2 : Extraction des CVE
bulletins = extract_cve_info(bulletins)
    
    # Étape 3 : Consolidation des données
dataframe_consolidation(bulletins)
    
    # Sauvegarde des URLs traitées
save_processed_urls("processed_urls.txt", new_urls)
end_time = time.time()
print(f"Temps total d'exécution : {int((end_time - start_time) // 60)} minutes et {(end_time - start_time) % 60:.2f} secondes")
