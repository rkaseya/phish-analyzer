"""Analyse des liens contenus dans un e-mail."""
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

# Domaines légitimes que les attaquants cherchent à imiter
DOMAINES_CONNUS = ["banque-exemple.example"]


def hote(url):
    """Étape A : renvoie le nom d'hôte d'une URL, en minuscules ('' si ce n'est pas une URL)."""
    return urlparse(url).hostname or ""
    


def extraire_liens(message):
    """Étape B : renvoie la liste des liens de l'e-mail : [{"url": ..., "texte": ...}, ...]."""
    liens = []
    partie_html = message.get_body(preferencelist=("html",))

    if partie_html is not None:
        # 1. Récupérer le contenu HTML
        contenu = partie_html.get_content()

        # 2. Trouver tous les couples (url, texte) avec re.findall
        couple_url_texte = re.findall(r'<a\s[^>]*href="([^"]+)"[^>]*>(.*?)</a>', contenu, re.IGNORECASE | re.DOTALL)
        
        # 3. Pour chaque couple, ajouter {"url": ..., "texte": ...} à liens
        #    (pense à .strip() pour enlever les espaces autour)
        for url, texte in couple_url_texte : 
            liens.append({"url": url.strip(), "texte": texte.strip()})

    else:
        partie_texte = message.get_body(preferencelist=("plain",))

        # 4. S'il y a une partie texte, chercher les URL avec : r"https?://[^\s]+"
        if partie_texte is not None:
            urls = re.findall(r"https?://[^\s]+", partie_texte.get_content(), re.IGNORECASE | re.DOTALL)

            # 5. Pour chaque URL, ajouter {"url": url, "texte": url}
            #    (dans un e-mail texte, ce qu'on voit EST l'URL)
            for url in urls:
                liens.append({"url": url, "texte": url})


    return liens

def est_sosie(nom_hote):
    """Étape C : True si le domaine ressemble à un domaine connu sans en être un."""
    for domaine_connu in DOMAINES_CONNUS:
        # 1. Si nom_hote EST domaine_connu, ou en est un sous-domaine → return False
        if nom_hote == domaine_connu or nom_hote.endswith("."+domaine_connu):
            return False
        # 2. Sinon, si la ressemblance (ratio) est >= 0.8 → return True
        elif SequenceMatcher(None, nom_hote, domaine_connu).ratio() >= 0.8:
            return True
            
    # 3. Aucun domaine connu ne lui ressemble → ce n'est pas un sosie
    return False





def analyser_liens(message):
    """Étape D : renvoie la liste des alertes liées aux liens."""
    alertes = []
    for url in extraire_liens(message):
        if not hote(url):
            alertes.append({"url": "ce lien n'est pas une lien url"})
        elif est_sosie:
            alertes.append({"sosie": "ce lien est un sosie d'un domaine connu"})
    return alertes # à compléter
