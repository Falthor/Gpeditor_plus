# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/) : une
section par date de livraison, la plus récente en premier. Ce fichier est la
source unique pour le panneau "Notes de version" du volet droit et pour
? > Patch note (voir `plan-gpedit-ui-enhancements.md` §2 et §3.d).

## 2026-07-23 — Options de sécurité complétées, arborescence corrigée

- Ajout de 66 paramètres manquants dans Stratégies locales > Options de
  sécurité (Comptes, Audit, Périphériques, Contrôleur/Membre de domaine,
  Ouverture de session interactive, Client/Serveur réseau Microsoft, Accès
  réseau, Sécurité réseau, Arrêt du système, Objets système, Contrôle de
  compte utilisateur) : 71 paramètres au total contre 5 auparavant.
- Correction : "Paramètres Windows" et "Paramètres de sécurité" sont
  désormais deux dossiers distincts dans l'arborescence, comme dans la
  console gpedit.msc standard, au lieu d'un unique noeud au libellé
  composé.

## 2026-07-23 — Menu horizontal, colonnes personnalisables, filtre CIS par profil

- Ajout d'un menu horizontal (Fichier / Affichage / ?) : Fichier > Quitter.
- Affichage > Ajout/suppression colonnes : nouvelle colonne "Recommended
  state" (valeur détaillée recommandée par le CIS) ; colonne "Portée"
  repassée masquée par défaut.
- Affichage > Profil : sélection du profil CIS actif (benchmark, version,
  niveau, rôle), filtre la liste sur les paramètres couverts par ce profil et
  pilote la colonne "Recommended state" ; bouton "Supprimer le filtre" pour
  revenir à l'état par défaut (OS le plus récent, niveau L1, rôle Member
  Server).
- Affichage > Langue : le sélecteur de langue quitte la barre de recherche et
  devient un sous-menu à choix unique.
- ? > À propos / Patch note / Benchmark : nouvelles fenêtres d'information.
- Le volet droit affiche désormais les notes de version (10 dernières
  entrées de ce fichier) tant qu'aucune catégorie n'a été sélectionnée dans
  l'arborescence ni aucune recherche lancée.
- Un fichier ADMX sans traduction ADML (ni langue demandée, ni langue de
  repli) n'est plus indexé du tout, au lieu d'afficher des libellés bruts non
  résolus.
