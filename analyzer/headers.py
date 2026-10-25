from email.utils import parseaddr


def domaine(valeur):
    """Renvoie le domaine d'une adresse e-mail, en minuscules ('' si absent)."""
    # 1. Si valeur est None ou vide, renvoyer ""
    if not valeur:
        return ""
    
    # 2. Extraire l'adresse avec parseaddr (pense à str(valeur))
    address = parseaddr(str(valeur))
    mail_address = address[1]

    # 3. S'il n'y a pas de @ dans l'adresse, renvoyer ""
    if '@' not in mail_address:
        return ""
    
    # 4. Renvoyer la partie après le @, en minuscules
    return mail_address.split("@")[1].lower()

def analyser_entetes(message):
    """Analyse les en-têtes et renvoie la liste des alertes."""
    return []  # à compléter à l'étape suivante