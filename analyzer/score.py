"""Score de risque et verdict, à partir des alertes de tous les modules."""
from analyzer.attachments import analyser_pieces_jointes
from analyzer.headers import analyser_entetes
from analyzer.links import analyser_liens

# Points de risque par type d'alerte : plus l'indice est fort, plus il pèse
POIDS = {
    "return_path": 10,           # fréquent même chez des expéditeurs légitimes (newsletters)
    "dkim": 10,
    "reply_to": 15,
    "spf": 15,
    "dmarc": 25,                 # le domaine affiché n'est pas authentifié
    "lien_trompeur": 25,
    "lien_ip": 30,
    "double_extension": 30,
    "domaine_sosie": 40,         # imitation délibérée d'une marque
    "extension_dangereuse": 40,  # fichier qui exécute du code
}
POIDS_PAR_DEFAUT = 10            # pour une alerte absente du barème
SCORE_MAX = 100

SEUIL_SUSPECT = 20
SEUIL_MALVEILLANT = 50


def calculer_score(alertes):
    """Étape A : somme des poids des alertes, plafonnée à SCORE_MAX."""
    somme = 0
    for alerte in alertes:
        code = alerte["code"]
        if code in POIDS:
            somme += POIDS[code]
        else:
            somme += POIDS_PAR_DEFAUT
    return min(somme, SCORE_MAX)


def verdict(score):
    """Étape B : "légitime" sous SEUIL_SUSPECT, "suspect" sous SEUIL_MALVEILLANT, sinon "malveillant"."""
    if score < SEUIL_SUSPECT: return "légitime"
    elif score < SEUIL_MALVEILLANT and score >= SEUIL_SUSPECT: return "suspect"
    else: return "malveillant"


def analyser_email(message):
    """Étape C : lance toutes les analyses et renvoie {"alertes": [...], "score": ..., "verdict": ...}."""
    liste_alertes = analyser_entetes(message) + analyser_liens(message) + analyser_pieces_jointes(message) 
    score = calculer_score(liste_alertes)
    return {"alertes": liste_alertes, "score": score, "verdict": verdict(score)} 
