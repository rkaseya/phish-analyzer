"""Tests de l'analyse des en-têtes.

Ils décrivent le comportement attendu : à toi d'écrire analyzer/headers.py
pour qu'ils passent tous (python -m pytest -v).
"""
from pathlib import Path

from analyzer.headers import analyser_entetes, domaine
from analyzer.parser import charger_email

from email.message import EmailMessage

SAMPLES = Path(__file__).parent.parent / "samples"


def codes_alertes(nom_fichier):
    """Renvoie l'ensemble des codes d'alerte levés pour un e-mail de test."""
    message = charger_email(SAMPLES / nom_fichier)
    return {alerte["code"] for alerte in analyser_entetes(message)}


# --- La fonction domaine() -------------------------------------------------

def test_domaine_adresse_simple():
    assert domaine("client@exemple.example") == "exemple.example"


def test_domaine_avec_nom_affiche():
    assert domaine("Banque Exemple <notifications@banque-exemple.example>") == "banque-exemple.example"


def test_domaine_en_minuscules():
    # Les noms de domaine ne sont pas sensibles à la casse
    assert domaine("<Securite@Banque-Exemple.EXAMPLE>") == "banque-exemple.example"


def test_domaine_en_tete_absent():
    # Un en-tête absent vaut None : la fonction ne doit pas planter
    assert domaine(None) == ""


# --- La fonction analyser_entetes() ----------------------------------------

def test_email_legitime_aucune_alerte():
    assert codes_alertes("legitime.eml") == set()


def test_usurpation_detectee():
    assert codes_alertes("phishing_usurpation.eml") == {"reply_to", "return_path", "spf", "dkim", "dmarc"}


def test_chaque_alerte_a_une_explication():
    message = charger_email(SAMPLES / "phishing_usurpation.eml")
    for alerte in analyser_entetes(message):
        assert alerte["detail"], f"l'alerte {alerte['code']} n'a pas d'explication"


def test_domaine_sosie_passe_les_entetes():
    # Un attaquant qui possède son propre domaine passe SPF, DKIM et DMARC :
    # l'analyse des en-têtes seule ne suffit pas (d'où l'analyse des liens ensuite)
    assert codes_alertes("phishing_piece_jointe.eml") == set()


def test_sans_authentication_results():
    message = EmailMessage()
    message["From"] = "contact@banque-exemple.example"
    # Pas d'en-tête Authentication-Results du tout
    codes = {alerte["code"] for alerte in analyser_entetes(message)}
    assert codes == {"dmarc","spf","dkim"}