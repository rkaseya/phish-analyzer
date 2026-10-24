from email import policy
from email.parser import BytesParser


def charger_email(chemin):
    """Lit un fichier .eml et renvoie l'e-mail sous forme d'objet Python."""
    with open(chemin, mode='rb') as fichier:
        return BytesParser(policy=policy.default).parse(fichier)