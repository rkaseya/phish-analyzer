import sys 
from analyzer.parser import charger_email


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <fichier.eml>")
        sys.exit(1)

    message = charger_email(sys.argv[1])
    print(f"De      : {message['From']}")
    print(f"Pour    : {message['To']}")
    print(f"Sujet   : {message['Subject']}")
    print(f"Date    : {message['Date']}")

if __name__ == "__main__":
    main()    