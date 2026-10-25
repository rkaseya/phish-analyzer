"""Analyse des liens contenus dans un e-mail."""
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

# Domaines légitimes que les attaquants cherchent à imiter
DOMAINES_CONNUS = ["banque-exemple.example"]


def hote(url):
    """Étape A : renvoie le nom d'hôte d'une URL, en minuscules ('' si ce n'est pas une URL)."""
    if not urlparse(url).hostname == None:
        return urlparse(url).hostname
    else: return ''
    


def extraire_liens(message):
    """Étape B : renvoie la liste des liens de l'e-mail : [{"url": ..., "texte": ...}, ...]."""
    return([{"url": url, "texte": url.hostname} for url in message])


def est_sosie(nom_hote):
    """Étape C : True si le domaine ressemble à un domaine connu sans en être un."""
    if nom_hote in DOMAINES_CONNUS:
        return True
    else: return False



def analyser_liens(message):
    """Étape D : renvoie la liste des alertes liées aux liens."""
    alertes = []
    for url in extraire_liens(message):
        if not hote(url):
            alertes.append({"url": "ce lien n'est pas une lien url"})
        elif est_sosie:
            alertes.append({"sosie": "ce lien est un sosie d'un domaine connu"})
    return alertes # à compléter
