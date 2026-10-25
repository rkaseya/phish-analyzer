"""Tests de l'analyse des pièces jointes (python -m pytest -v tests/test_attachments.py)."""
from email.message import EmailMessage
from pathlib import Path

from analyzer.attachments import (
    analyser_pieces_jointes,
    double_extension,
    extension_dangereuse,
    lister_pieces_jointes,
    sha256,
)
from analyzer.parser import charger_email

SAMPLES = Path(__file__).parent.parent / "samples"


def charger(nom_fichier):
    return charger_email(SAMPLES / nom_fichier)


def codes_alertes(nom_fichier):
    return {alerte["code"] for alerte in analyser_pieces_jointes(charger(nom_fichier))}


# --- Étape A : sha256() -----------------------------------------------------

def test_sha256_valeur_connue():
    # Empreinte de référence de b"abc", publiée dans la norme SHA-256
    assert sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_contenus_differents_empreintes_differentes():
    assert sha256(b"facture") != sha256(b"Facture")


# --- Étape B : extension_dangereuse() ---------------------------------------

def test_executable_est_dangereux():
    assert extension_dangereuse("setup.exe") is True


def test_extension_insensible_a_la_casse():
    assert extension_dangereuse("FACTURE.EXE") is True


def test_pdf_n_est_pas_dangereux():
    assert extension_dangereuse("releve_octobre.pdf") is False


def test_fichier_sans_extension():
    assert extension_dangereuse("LISEZMOI") is False


# --- Étape C : double_extension() -------------------------------------------

def test_double_extension_piegee():
    # S'affiche souvent "facture_octobre.pdf" quand Windows masque les extensions
    assert double_extension("facture_octobre.pdf.exe") is True


def test_double_extension_majuscules():
    assert double_extension("Photo.JPG.scr") is True


def test_simple_extension_n_est_pas_double():
    assert double_extension("setup.exe") is False


def test_points_dans_le_nom_mais_fichier_inoffensif():
    assert double_extension("rapport.v2.final.pdf") is False


# --- Étape D : lister_pieces_jointes() --------------------------------------

def test_liste_vide_sans_piece_jointe():
    assert lister_pieces_jointes(charger("legitime.eml")) == []


def test_liste_piece_jointe():
    assert lister_pieces_jointes(charger("phishing_piece_jointe.eml")) == [
        {
            "nom": "facture_octobre.pdf.exe",
            "taille": 59,
            "sha256": "b64f7fd6498b669914d96a30f68a1531e3187d26dd7cfe774aca12a9457c840a",
        }
    ]


# --- Étape E : analyser_pieces_jointes() ------------------------------------

def test_pas_d_alerte_sans_piece_jointe():
    assert codes_alertes("legitime.eml") == set()
    assert codes_alertes("phishing_usurpation.eml") == set()


def test_piece_jointe_piegee_detectee():
    assert codes_alertes("phishing_piece_jointe.eml") == {"extension_dangereuse", "double_extension"}


def test_piece_jointe_inoffensive_aucune_alerte():
    message = EmailMessage()
    message.set_content("Votre relevé est en pièce jointe.")
    message.add_attachment(b"%PDF-1.4 contenu", maintype="application", subtype="pdf", filename="releve.pdf")
    assert analyser_pieces_jointes(message) == []


def test_chaque_alerte_piece_jointe_a_une_explication():
    for alerte in analyser_pieces_jointes(charger("phishing_piece_jointe.eml")):
        assert alerte["detail"], f"l'alerte {alerte['code']} n'a pas d'explication"

def test_nom_sans_point_n_a_pas_d_extension():
    # Un fichier nommé simplement "exe" n'a pas d'extension
    assert extension_dangereuse("exe") is False

def test_numero_de_version_n_est_pas_une_double_extension():
    # Nom d'installeur légitime : "1" n'est pas une extension leurre
    assert double_extension("python-3.12.1.exe") is False