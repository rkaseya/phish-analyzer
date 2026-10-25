"""Analyse des pièces jointes d'un e-mail."""
import hashlib

# Extensions qui exécutent du code à l'ouverture (exécutables, scripts, macros…)
EXTENSIONS_DANGEREUSES = {
    "exe", "scr", "bat", "cmd", "com", "pif", "msi",   # exécutables Windows
    "js", "vbs", "ps1", "hta", "jar", "lnk",           # scripts et raccourcis
    "docm", "xlsm", "pptm",                            # documents Office avec macros
    "iso", "img",                                      # images disque
}

# Extensions « rassurantes » qu'un attaquant place avant la vraie extension
EXTENSIONS_LEURRES = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}


def sha256(contenu):
    """Étape A : renvoie l'empreinte SHA-256 (en hexadécimal) d'un contenu en octets."""
    return hashlib.sha256(contenu).hexdigest()


def extension_dangereuse(nom_fichier):
    """Étape B : True si la dernière extension du fichier est dans EXTENSIONS_DANGEREUSES."""
    nom_fichier_segmente = nom_fichier.lower().split(".")
    return len(nom_fichier_segmente) >= 2 and nom_fichier_segmente[-1] in EXTENSIONS_DANGEREUSES
       
            


def double_extension(nom_fichier):
    """Étape C : True si une extension leurre précède une extension dangereuse (ex. .pdf.exe)."""
    nom_fichier_segmente = nom_fichier.lower().split(".")
    return len(nom_fichier_segmente) >= 3 and nom_fichier_segmente[-1] in EXTENSIONS_DANGEREUSES and nom_fichier_segmente[-2] in EXTENSIONS_LEURRES


def lister_pieces_jointes(message):
    """Étape D : renvoie [{"nom": ..., "taille": ..., "sha256": ...}, ...] pour chaque pièce jointe."""
    return []  # à compléter


def analyser_pieces_jointes(message):
    """Étape E : renvoie la liste des alertes liées aux pièces jointes."""
    return []  # à compléter
