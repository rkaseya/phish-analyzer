"""Tests du rapport HTML (python -m pytest -v tests/test_rapport.py)."""
from email.message import EmailMessage
from pathlib import Path

from analyzer.attachments import lister_pieces_jointes
from analyzer.parser import charger_email
from analyzer.rapport import generer_html, ligne_alerte, ligne_piece_jointe
from analyzer.score import analyser_email

SAMPLES = Path(__file__).parent.parent / "samples"
DATE = "25/10/2026 à 20:30"


def rapport(message):
    return generer_html(message, analyser_email(message), lister_pieces_jointes(message), DATE)


# --- Étape A : ligne_alerte() -----------------------------------------------

def test_ligne_alerte_contient_code_et_detail():
    ligne = ligne_alerte({"code": "spf", "detail": "Échec de la vérification SPF"})
    assert ligne.startswith("<tr>") and ligne.endswith("</tr>")
    assert "<code>spf</code>" in ligne
    assert "Échec de la vérification SPF" in ligne


def test_ligne_alerte_echappe_le_html():
    # Le détail peut contenir du texte venu de l'e-mail : il ne doit jamais être interprété
    ligne = ligne_alerte({"code": "lien_trompeur", "detail": "<script>alert(1)</script>"})
    assert "<script>" not in ligne
    assert "&lt;script&gt;" in ligne


# --- Étape B : ligne_piece_jointe() -----------------------------------------

def test_ligne_piece_jointe():
    ligne = ligne_piece_jointe({"nom": "facture.pdf.exe", "taille": 59, "sha256": "abc123"})
    assert ligne.startswith("<tr>") and ligne.endswith("</tr>")
    assert "facture.pdf.exe" in ligne and "59 octets" in ligne
    assert "<code>abc123</code>" in ligne


def test_ligne_piece_jointe_echappe_le_nom():
    # Le nom du fichier est choisi par l'expéditeur, donc potentiellement par un attaquant
    ligne = ligne_piece_jointe({"nom": "<b>piege</b>.exe", "taille": 1, "sha256": "x"})
    assert "<b>" not in ligne


# --- Étape C : generer_html() -----------------------------------------------

def test_page_html_complete():
    page = rapport(charger_email(SAMPLES / "legitime.eml"))
    assert page.startswith("<!DOCTYPE html>")
    assert "$" not in page, "un $nom du modèle n'a pas été remplacé"


def test_rapport_email_legitime():
    page = rapport(charger_email(SAMPLES / "legitime.eml"))
    assert "LÉGITIME" in page
    assert 'class="badge legitime"' in page
    assert "Votre relevé de compte d&#x27;octobre est disponible" in page
    assert "Aucune alerte" in page
    assert DATE in page


def test_rapport_email_malveillant():
    page = rapport(charger_email(SAMPLES / "phishing_piece_jointe.eml"))
    assert "MALVEILLANT" in page
    assert 'class="badge malveillant"' in page
    for code in ("domaine_sosie", "extension_dangereuse", "double_extension"):
        assert f"<code>{code}</code>" in page
    assert "b64f7fd6498b669914d96a30f68a1531e3187d26dd7cfe774aca12a9457c840a" in page


def test_sujet_piege_est_echappe():
    # Un attaquant contrôle le sujet : sans échappement, ouvrir le rapport exécuterait son code (XSS)
    message = EmailMessage()
    message["From"] = "contact@banque-exemple.example"
    message["Subject"] = '<img src=x onerror="alert(1)">'
    message.set_content("Bonjour")
    page = rapport(message)
    assert "<img" not in page
    assert "&lt;img" in page
