import re
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
    alertes = []
    domaine_from = domaine(message["From"])

    # --- Partie A : Reply-To et Return-Path ---
    # Pour Reply-To :
    #   - calculer son domaine
    domaine_reply_to = domaine(message["Reply-To"])

    #   - s'il n'est pas vide ET différent de domaine_from,
    #     ajouter {"code": "reply_to", "detail": "..."} à la liste
    if domaine_reply_to and domaine_reply_to != domaine_from:
        alertes.append({"code": "reply_to", "detail" : f"Reply-To pointe vers {domaine_reply_to} au lieu de {domaine_from}"})
                        
    # Même chose pour Return-Path, avec le code "return_path"
    domaine_return_path = domaine(message["Return-Path"])
    if domaine_return_path and domaine_return_path != domaine_from:
        alertes.append({"code" : "return_path", "detail": f"Return-path pointe vers {domaine_return_path} au lieu de {domaine_from}"})

    # --- Partie B : SPF, DKIM, DMARC ---
    # (on verra après)

    return alertes