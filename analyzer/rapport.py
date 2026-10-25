"""Génération du rapport d'analyse au format HTML."""
import html
from string import Template

# Modèle de page : chaque $nom est remplacé par une valeur dans generer_html()
MODELE = Template("""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishAnalyzer – $sujet</title>
<style>
  :root { --fond:#f6f8fa; --carte:#fff; --texte:#1f2328; --gris:#59636e; --bord:#d0d7de;
          --legitime:#1a7f37; --suspect:#9a6700; --malveillant:#cf222e; }
  * { box-sizing: border-box; }
  body { margin:0; padding:32px 16px; background:var(--fond); color:var(--texte);
         font-family:-apple-system,"Segoe UI",Helvetica,Arial,sans-serif; }
  main { max-width:900px; margin:0 auto; }
  h1 { font-size:24px; margin:0 0 4px; }
  h2 { font-size:17px; margin:0 0 12px; }
  .meta { color:var(--gris); font-size:14px; }
  section { background:var(--carte); border:1px solid var(--bord); border-radius:8px;
            padding:20px; margin-top:20px; overflow-x:auto; }
  .verdict { display:flex; align-items:center; gap:20px; flex-wrap:wrap; }
  .badge { color:#fff; font-weight:700; font-size:20px; padding:8px 18px; border-radius:6px; }
  .legitime { background:var(--legitime); } .suspect { background:var(--suspect); }
  .malveillant { background:var(--malveillant); }
  .jauge { flex:1; min-width:200px; height:10px; background:#eaeef2; border-radius:5px; overflow:hidden; }
  .jauge div { height:100%; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:9px 8px; border-bottom:1px solid var(--bord); vertical-align:top; }
  th { color:var(--gris); width:110px; }
  code { background:var(--fond); padding:2px 6px; border-radius:4px; font-size:13px; word-break:break-all; }
  td:first-child code { white-space:nowrap; word-break:normal; }
  td { overflow-wrap:anywhere; }
  .vide { color:var(--gris); }
</style>
</head>
<body>
<main>
  <h1>Rapport d'analyse</h1>
  <div class="meta">PhishAnalyzer · généré le $date_rapport</div>

  <section class="verdict">
    <span class="badge $classe_verdict">$verdict</span>
    <div class="jauge"><div class="$classe_verdict" style="width:$score%"></div></div>
    <strong>$score / 100</strong>
  </section>

  <section>
    <h2>E-mail analysé</h2>
    <table>
      <tr><th>De</th><td>$expediteur</td></tr>
      <tr><th>Pour</th><td>$destinataire</td></tr>
      <tr><th>Sujet</th><td>$sujet</td></tr>
      <tr><th>Date</th><td>$date_email</td></tr>
    </table>
  </section>

  <section>
    <h2>Alertes ($nombre_alertes)</h2>
    <table>
      $lignes_alertes
    </table>
  </section>

  <section>
    <h2>Pièces jointes ($nombre_pieces_jointes)</h2>
    <table>
      $lignes_pieces_jointes
    </table>
  </section>
</main>
</body>
</html>
""")


def echapper(valeur):
    """Rend un texte inoffensif avant de l'insérer dans la page (protection contre le XSS).

    Tout ce qui vient de l'e-mail (sujet, expéditeur, noms de fichiers, détails des alertes)
    est choisi par l'expéditeur, donc potentiellement par un attaquant : <, >, &, " et '
    sont remplacés par leurs entités HTML pour être affichés, jamais interprétés.
    """
    return html.escape(str(valeur or ""))


def ligne_alerte(alerte):
    """Renvoie une ligne de tableau HTML pour une alerte, contenu échappé.

    Exemple : <tr><td><code>spf</code></td><td>Échec de la vérification SPF…</td></tr>
    """
    return f"<tr><td><code>{echapper(alerte['code'])}</code></td><td>{echapper(alerte['detail'])}</td></tr>"


def ligne_piece_jointe(piece_jointe):
    """Renvoie une ligne de tableau HTML pour une pièce jointe, contenu échappé.

    Exemple : <tr><td>facture.pdf.exe (59 octets)</td><td><code>b64f7f…</code></td></tr>
    """
    return (
        f"<tr><td>{echapper(piece_jointe['nom'])} ({piece_jointe['taille']} octets)</td>"
        f"<td><code>{echapper(piece_jointe['sha256'])}</code></td></tr>"
    )


def ligne_vide(texte):
    """Ligne affichée quand une section ne contient rien."""
    return f'<tr><td class="vide">{texte}</td></tr>'


def generer_html(message, resultat, pieces_jointes, date_rapport):
    """Renvoie la page HTML complète du rapport."""
    alertes = resultat["alertes"]
    lignes_alertes = "\n".join(ligne_alerte(alerte) for alerte in alertes) or ligne_vide("Aucune alerte.")
    lignes_pieces_jointes = (
        "\n".join(ligne_piece_jointe(piece) for piece in pieces_jointes) or ligne_vide("Aucune pièce jointe.")
    )

    # Nom de classe CSS sans accent : "légitime" → "legitime"
    classe_verdict = resultat["verdict"].replace("é", "e")

    return MODELE.substitute(
        sujet=echapper(message["Subject"]),
        expediteur=echapper(message["From"]),
        destinataire=echapper(message["To"]),
        date_email=echapper(message["Date"]),
        date_rapport=echapper(date_rapport),
        verdict=echapper(resultat["verdict"].upper()),
        classe_verdict=classe_verdict,
        score=int(resultat["score"]),
        nombre_alertes=len(alertes),
        lignes_alertes=lignes_alertes,
        nombre_pieces_jointes=len(pieces_jointes),
        lignes_pieces_jointes=lignes_pieces_jointes,
    )
