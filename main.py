import argparse
from datetime import datetime
from pathlib import Path

from analyzer.attachments import lister_pieces_jointes
from analyzer.parser import charger_email
from analyzer.rapport import generer_html
from analyzer.score import analyser_email





def main():
    # argparse lit les arguments et génère automatiquement l'aide (python main.py --help)
    parseur = argparse.ArgumentParser(description="Analyse un e-mail suspect (.eml) et rend un verdict.")
    parseur.add_argument("fichier", help="chemin du fichier .eml à analyser")
    parseur.add_argument("--html", metavar="RAPPORT", help="enregistre aussi un rapport HTML à cet emplacement")
    arguments = parseur.parse_args()

    message = charger_email(arguments.fichier)
    resultat = analyser_email(message)

    print("=== PhishAnalyzer ===")
    print()
    print(f"De      : {message['From']}")
    print(f"Pour    : {message['To']}")
    print(f"Sujet   : {message['Subject']}")
    print(f"Date    : {message['Date']}")
    print()
    print(f"Verdict : {resultat['verdict'].upper()} (score {resultat['score']}/100)")
    print()

    # --- Étape 4 : les alertes ---
    alertes = resultat['alertes']
    if alertes:
        print(f"Alertes ({len(alertes)}) :")
        for alerte in alertes:
           print(f"  [{alerte['code']}] {alerte['detail']}")
    else:
        print("Aucune alerte.")

    # --- Étape 5 : les pièces jointes ---
    pieces_jointes = lister_pieces_jointes(message)
    if pieces_jointes:
        print()
        print(f"Pièces jointes ({len(pieces_jointes)}) :")
        for piece_jointe in pieces_jointes:
            print(f"  {piece_jointe['nom']} ({piece_jointe['taille']} octets)")
            print(f"  SHA-256 : {piece_jointe['sha256']}")

    # --- Rapport HTML (option --html) ---
    if arguments.html:
        date_rapport = datetime.now().strftime("%d/%m/%Y à %H:%M")
        page = generer_html(message, resultat, pieces_jointes, date_rapport)
        chemin = Path(arguments.html)
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text(page, encoding="utf-8")
        print()
        print(f"Rapport HTML : {chemin}")

if __name__ == "__main__":
    main()