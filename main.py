import sys 
from analyzer.parser import charger_email
from analyzer.score import analyser_email
from analyzer.attachments import lister_pieces_jointes





def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <fichier.eml>")
        sys.exit(1)

    message = charger_email(sys.argv[1])
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

if __name__ == "__main__":
    main()