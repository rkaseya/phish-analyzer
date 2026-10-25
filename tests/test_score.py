"""Tests du score et du verdict (python -m pytest -v tests/test_score.py)."""
from pathlib import Path

from analyzer.parser import charger_email
from analyzer.score import analyser_email, calculer_score, verdict

SAMPLES = Path(__file__).parent.parent / "samples"


def alertes(*codes):
    """Fabrique une liste d'alertes à partir de codes, pour les tests."""
    return [{"code": code, "detail": "test"} for code in codes]


# --- Étape A : calculer_score() ---------------------------------------------

def test_aucune_alerte_score_nul():
    assert calculer_score([]) == 0


def test_score_somme_des_poids():
    # reply_to (15) + spf (15)
    assert calculer_score(alertes("reply_to", "spf")) == 30


def test_code_inconnu_compte_le_poids_par_defaut():
    # Une alerte que le barème ne connaît pas encore ne doit pas être ignorée
    assert calculer_score(alertes("nouvelle_alerte")) == 10


def test_score_plafonne_a_100():
    assert calculer_score(alertes("domaine_sosie", "extension_dangereuse", "double_extension")) == 100


# --- Étape B : verdict() ----------------------------------------------------

def test_verdict_legitime():
    assert verdict(0) == "légitime"
    assert verdict(19) == "légitime"


def test_verdict_suspect():
    assert verdict(20) == "suspect"
    assert verdict(49) == "suspect"


def test_verdict_malveillant():
    assert verdict(50) == "malveillant"
    assert verdict(100) == "malveillant"


# --- Étape C : analyser_email() ---------------------------------------------

def test_analyse_complete_email_legitime():
    resultat = analyser_email(charger_email(SAMPLES / "legitime.eml"))
    assert resultat == {"alertes": [], "score": 0, "verdict": "légitime"}


def test_analyse_complete_usurpation():
    resultat = analyser_email(charger_email(SAMPLES / "phishing_usurpation.eml"))
    assert len(resultat["alertes"]) == 7     # 5 en-têtes + 2 liens
    assert resultat["verdict"] == "malveillant"


def test_analyse_complete_piece_jointe():
    resultat = analyser_email(charger_email(SAMPLES / "phishing_piece_jointe.eml"))
    assert {a["code"] for a in resultat["alertes"]} == {"domaine_sosie", "extension_dangereuse", "double_extension"}
    assert resultat["score"] == 100
    assert resultat["verdict"] == "malveillant"
