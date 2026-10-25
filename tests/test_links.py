"""Tests de l'analyse des liens (python -m pytest -v tests/test_links.py)."""
from pathlib import Path

from analyzer.links import analyser_liens, est_sosie, extraire_liens, hote
from analyzer.parser import charger_email

from email.message import EmailMessage

SAMPLES = Path(__file__).parent.parent / "samples"


def charger(nom_fichier):
    return charger_email(SAMPLES / nom_fichier)


def codes_alertes(nom_fichier):
    return {alerte["code"] for alerte in analyser_liens(charger(nom_fichier))}


# --- Étape A : hote() -------------------------------------------------------

def test_hote_url_simple():
    assert hote("https://www.banque-exemple.example/connexion") == "www.banque-exemple.example"


def test_hote_adresse_ip():
    assert hote("http://203.0.113.45/banque-exemple/connexion.php") == "203.0.113.45"


def test_hote_en_minuscules():
    assert hote("https://WWW.Banque-Exemple.EXAMPLE") == "www.banque-exemple.example"


def test_hote_texte_qui_n_est_pas_une_url():
    assert hote("Cliquez ici") == ""


# --- Étape B : extraire_liens() ---------------------------------------------

def test_extraction_html_legitime():
    assert extraire_liens(charger("legitime.eml")) == [
        {"url": "https://www.banque-exemple.example", "texte": "https://www.banque-exemple.example"}
    ]


def test_extraction_html_texte_different_de_l_url():
    # Le texte affiché à l'écran n'est pas la vraie destination du lien
    assert extraire_liens(charger("phishing_usurpation.eml")) == [
        {"url": "http://203.0.113.45/banque-exemple/connexion.php",
         "texte": "https://www.banque-exemple.example/connexion"}
    ]


def test_extraction_texte_brut_sans_html():
    # Pas de partie HTML : on cherche les URL dans le texte, le texte affiché est l'URL elle-même
    assert extraire_liens(charger("phishing_piece_jointe.eml")) == [
        {"url": "https://banque-exernple.example/paiement",
         "texte": "https://banque-exernple.example/paiement"}
    ]


# --- Étape C : est_sosie() --------------------------------------------------

def test_vrai_domaine_n_est_pas_un_sosie():
    assert est_sosie("banque-exemple.example") is False


def test_sous_domaine_du_vrai_domaine_n_est_pas_un_sosie():
    assert est_sosie("www.banque-exemple.example") is False


def test_domaine_ressemblant_est_un_sosie():
    # "rn" au lieu de "m" : presque invisible à l'œil nu
    assert est_sosie("banque-exernple.example") is True


def test_domaine_sans_rapport_n_est_pas_un_sosie():
    assert est_sosie("meteo-locale.example") is False


# --- Étape D : analyser_liens() ---------------------------------------------

def test_liens_legitimes_aucune_alerte():
    assert codes_alertes("legitime.eml") == set()


def test_lien_vers_ip_et_texte_trompeur():
    assert codes_alertes("phishing_usurpation.eml") == {"lien_ip", "lien_trompeur"}


def test_lien_vers_domaine_sosie():
    assert codes_alertes("phishing_piece_jointe.eml") == {"domaine_sosie"}


def test_chaque_alerte_lien_a_une_explication():
    for nom in ("phishing_usurpation.eml", "phishing_piece_jointe.eml"):
        for alerte in analyser_liens(charger(nom)):
            assert alerte["detail"], f"l'alerte {alerte['code']} n'a pas d'explication"



def test_lien_cliquez_ici_n_est_pas_trompeur():
    message = EmailMessage()
    message.set_content("Version texte")
    message.add_alternative(
        '<a href="https://www.banque-exemple.example/compte">Cliquez ici</a>',
        subtype="html",
    )
    assert analyser_liens(message) == []