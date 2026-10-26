# Kortex Security --- Spécification du client Next.js (MVP)

**Objectif :** construire le frontend web de Kortex Security en
réutilisant le backend Kortex déjà présent en local. La première
intégration concerne **Shasec uniquement**. L'intégration de **Hermes +
MCP HexStrike** viendra dans une deuxième phase et ne doit pas être
implémentée maintenant.

> Instruction importante pour Claude : commence par inspecter le dépôt
> existant et le backend local avant de modifier quoi que ce soit.
> Réutilise l'architecture, les conventions, les composants, les routes
> et l'authentification déjà présents. Ne crée pas un second backend et
> n'invente pas des endpoints. Si une information manque, signale-la et
> demande confirmation plutôt que de supposer.

------------------------------------------------------------------------

## 1. Contexte technique connu

### Services déjà déployés sur le VPS

-   Shasec tourne dans un service Docker `shasec-api-1`, image
    `ghcr.io/shalom-302/shasec:latest`.
-   L'API Shasec écoute sur le port conteneur `8000`.
-   Hermes Defender tourne dans un service séparé, sans port publié
    directement.
-   Shasec et Hermes partagent le réseau Docker
    `whatsapp-shared-network`.
-   HexStrike est utilisé par Hermes via MCP.
-   **Hermes ne fait pas partie du périmètre de cette première version
    du frontend.**

### Routes Shasec déjà repérées

Les routes ci-dessous ont été repérées dans le code de Shasec et/ou dans
son skill. Le frontend doit passer par le backend Kortex existant, et
non appeler directement Shasec depuis le navigateur.

  Fonction                       Route Shasec identifiée
  ------------------------------ ------------------------------------------
  Créer/lancer un scan rapide    `POST /api/v1/scans/quick`
  Lire un scan                   `GET /api/v1/scans/{id}`
  Lister les scans               `GET /api/v1/scans/`
  Lire la progression            `GET /api/v1/scans/{id}/progress`
  Lire les findings              `GET /api/v1/scans/{id}/findings`
  Lire l'analyse IA              `GET /api/v1/scans/{id}/analysis`
  Générer un rapport             `POST /api/v1/scans/{id}/report`
  Télécharger un rapport         `GET /api/v1/scans/{id}/report/download`
  Lister les cibles              `GET /api/v1/targets/`
  Créer une cible                `POST /api/v1/targets/`
  Autoriser/révoquer une cible   `POST /api/v1/targets/{id}/authorize`

Ces routes sont celles de Shasec, pas nécessairement celles du backend
Kortex. **Claude doit inspecter le backend Kortex local pour déterminer
les routes réellement disponibles pour le frontend.** Les routes Shasec
sont une référence d'intégration côté serveur.

Le skill Hermes/Shasec mentionne une authentification par jeton Bearer
et un scan rapide avec un payload de la forme :

``` json
{
  "url": "https://example.com",
  "profile": "standard"
}
```

Ne pas coder en dur les identifiants, tokens, clés API, noms d'hôtes de
production ou secrets.

------------------------------------------------------------------------

## 2. Objectif produit de cette première phase

Créer le client web responsive de **Kortex Security**, une plateforme
self-service permettant à un développeur ou à une PME de :

1.  créer un compte et se connecter via le mécanisme déjà géré par le
    backend Kortex ;
2.  accéder à un dashboard ;
3.  ajouter et gérer ses applications/domaines autorisés ;
4.  lancer un scan Shasec sur une cible autorisée ;
5.  suivre la progression d'un scan ;
6.  consulter les vulnérabilités détectées ;
7.  consulter l'analyse IA disponible ;
8.  consulter et télécharger un rapport lorsque le backend l'expose ;
9.  consulter son historique de scans et les états des tâches.

Ne pas implémenter pour l'instant : - l'intégration Hermes ou HexStrike
côté frontend ; - un nouvel orchestrateur de pentest ; - une nouvelle
API ou un nouveau backend ; - un système de paiement réel si le backend
local ne le prend pas déjà en charge ; - une consommation de crédits
simulée présentée comme réelle ; - des alertes WhatsApp ou email si les
endpoints et le flux ne sont pas déjà disponibles ; - des fonctions
d'exploitation automatique de vulnérabilités.

------------------------------------------------------------------------

## 3. Étape zéro obligatoire : auditer le dépôt local

Avant toute modification, Claude doit :

1.  examiner la structure du dépôt et identifier le framework, la
    version de Next.js, le gestionnaire de paquets et les conventions
    existantes ;
2.  repérer les variables d'environnement et le mode de configuration de
    l'URL API ;
3.  examiner le backend Kortex local : routes, schémas,
    authentification, format des réponses, gestion des erreurs, CORS et
    intégration Shasec ;
4.  identifier les fonctions qui existent déjà et les réutiliser ;
5.  produire un bref état des lieux : routes utilisables, routes
    manquantes, pages existantes, risques de régression ;
6.  seulement ensuite proposer un plan de modifications minimal.

**Ne pas remplacer un backend fonctionnel et ne pas créer de routes
supposées.** Si le backend Kortex ne possède pas encore un endpoint
nécessaire, le signaler clairement et proposer le contrat API à ajouter
séparément. Ne pas implémenter cette route sans vérifier les conventions
du projet et obtenir l'accord si le périmètre initial est frontend
uniquement.

------------------------------------------------------------------------

## 4. Pages et parcours utilisateur

### 4.1 Authentification

-   Page de connexion et, si le backend le permet, page d'inscription.
-   Utiliser le système d'authentification existant.
-   Ne jamais stocker de secret de service Shasec dans le navigateur.
-   Gérer les sessions expirées et les réponses `401` de façon propre.
-   Protéger les pages privées.

### 4.2 Dashboard

Afficher, selon les données réellement disponibles : - nombre de scans
; - derniers scans et leur statut ; - nombre de findings par niveau de
gravité, si les données sont disponibles ; - raccourci pour lancer un
scan ; - raccourci vers les cibles.

Ne pas afficher de statistiques fictives. Prévoir des états de
chargement, vides et d'erreur.

### 4.3 Applications / cibles

-   Liste des cibles de l'utilisateur.
-   Formulaire pour ajouter une URL ou un domaine.
-   Détail de la cible et statut d'autorisation.
-   Indiquer clairement qu'un utilisateur doit posséder la cible ou
    disposer d'une autorisation explicite avant de la scanner.
-   Utiliser le backend Kortex pour les opérations. Ne pas appeler
    directement Shasec depuis le navigateur.

Si le backend ne gère pas encore les cibles, afficher cette dépendance
dans le rapport d'audit et proposer une solution d'intégration ; ne pas
contourner les contrôles de sécurité.

### 4.4 Lancer un scan

-   Choisir une cible préalablement autorisée.
-   Sélectionner uniquement les profils de scan pris en charge par le
    backend.
-   Afficher un récapitulatif avant lancement.
-   Afficher une confirmation et l'identifiant du scan après lancement.
-   Empêcher les doubles soumissions.
-   Afficher un message explicite si la cible n'est pas autorisée ou si
    le lancement échoue.

Le scan doit être déclenché via le backend Kortex, qui appelle Shasec
côté serveur. Ne jamais exposer les identifiants Shasec au frontend.

### 4.5 Détail et progression du scan

Afficher : - cible et date ; - statut et progression, lorsque
disponibles ; - étapes du scan, si le backend les fournit ; - messages
d'erreur compréhensibles ; - findings et leur gravité ; - analyse IA, si
elle existe ; - rapport téléchargeable, si disponible.

Utiliser le mécanisme de polling déjà adopté par le projet. À défaut,
utiliser un polling raisonnable avec arrêt lorsque le scan est terminé
ou échoué. Ne pas mettre en place une boucle de requêtes agressive.

### 4.6 Historique

-   Tableau ou liste paginée des scans.
-   Filtres par cible, statut et date seulement si les données et routes
    le permettent.
-   Lien vers le détail du scan.
-   Gérer les états vides et les erreurs de chargement.

------------------------------------------------------------------------

## 5. Design et expérience utilisateur

-   Interface professionnelle de cybersécurité, sobre, moderne et
    lisible.
-   Priorité à la clarté des statuts et des vulnérabilités, pas aux
    animations décoratives.
-   Responsive desktop, tablette et mobile.
-   Réutiliser le design system et les composants déjà installés.
-   Si le dépôt utilise déjà Tailwind et shadcn/ui, continuer avec ces
    outils plutôt que d'en ajouter d'autres.
-   Si le dépôt a déjà une identité visuelle Kortex, la respecter.
-   Accessibilité : contrastes suffisants, labels explicites, navigation
    clavier et retours d'erreur lisibles.
-   Les badges de gravité doivent correspondre aux valeurs reçues du
    backend ; ne pas inventer une gravité si elle manque.

### Navigation suggérée

-   Dashboard
-   Mes applications / Cibles
-   Scans
-   Rapports
-   Crédits / Abonnement (afficher seulement si pris en charge par le
    backend)
-   Paramètres du compte

Ne pas afficher des écrans de paiement ou de crédits fonctionnels s'ils
ne sont pas reliés à des endpoints réels. Une page « bientôt disponible
» peut être utilisée si nécessaire, à condition d'être explicitement
présentée comme telle.

------------------------------------------------------------------------

## 6. Architecture frontend attendue

Adapter ces recommandations à l'architecture existante plutôt que de les
imposer aveuglément.

-   Centraliser les appels API dans un client partagé.
-   Configurer l'URL du backend par variable d'environnement publique
    dédiée, par exemple `NEXT_PUBLIC_API_BASE_URL`, uniquement si c'est
    compatible avec le projet.
-   Garder les secrets exclusivement côté serveur.
-   Typage TypeScript pour les objets réellement confirmés :
    utilisateur, cible, scan, finding, rapport.
-   Gérer les erreurs réseau, `401`, `403`, `404`, `422` et `5xx`.
-   Ne pas dupliquer la logique métier du backend dans les composants.
-   Ne pas faire confiance aux identifiants ou statuts envoyés par le
    navigateur : le backend doit vérifier les autorisations.
-   Respecter le format d'enveloppe des réponses déjà utilisé par l'API.

### Variables d'environnement

-   Documenter les variables nécessaires dans `.env.example`.
-   Ne jamais écrire de vraies clés ou de vrais tokens dans
    `.env.example`.
-   Ne pas modifier les fichiers `.env` existants sans raison.
-   Ne pas exposer une URL interne Docker dans le bundle client. Le
    navigateur doit utiliser l'URL accessible du backend Kortex.

------------------------------------------------------------------------

## 7. Sécurité et limites

-   Le frontend ne doit jamais pouvoir choisir des commandes MCP, des
    outils shell ou des commandes de pentest arbitraires.
-   Les cibles doivent être validées côté serveur et associées à
    l'utilisateur.
-   Ne pas faire confiance à un contrôle frontend comme unique mécanisme
    d'autorisation.
-   Ne pas afficher les logs internes, secrets, tokens ou stack traces
    aux clients.
-   Les erreurs destinées aux utilisateurs doivent être explicites sans
    révéler l'infrastructure.
-   Ne pas introduire de fonction d'exploitation intrusive.
-   Les actions de scan doivent respecter le périmètre autorisé et les
    protections existantes de Shasec.
-   Le backend doit vérifier que les données consultées appartiennent au
    compte connecté.

------------------------------------------------------------------------

## 8. Critères d'acceptation

Le travail est considéré terminé lorsque :

-   [ ] Le frontend démarre avec les commandes du dépôt existant.
-   [ ] L'authentification utilise le backend existant.
-   [ ] Les pages privées sont protégées.
-   [ ] Le dashboard utilise des données réelles ou affiche un état vide
    clair.
-   [ ] L'utilisateur peut consulter ses cibles via le backend.
-   [ ] L'utilisateur peut lancer un scan via le backend Kortex lorsque
    la route existe.
-   [ ] L'utilisateur peut consulter l'état et les résultats d'un scan.
-   [ ] Les rapports peuvent être ouverts/téléchargés si le backend le
    permet.
-   [ ] Les états de chargement, vides et erreurs sont traités.
-   [ ] Aucun secret Shasec/Hermes n'est présent dans le code client.
-   [ ] Aucun endpoint inventé ou faux résultat n'est présenté comme
    réel.
-   [ ] Les contrôles de propriété et d'autorisation restent côté
    serveur.
-   [ ] Les tests et le lint du projet passent, dans la mesure où ils
    existent déjà.

------------------------------------------------------------------------

## 9. Livrables attendus de Claude

1.  Un audit succinct du dépôt et du backend local.
2.  Une liste des endpoints Kortex réellement utilisables par le
    frontend.
3.  Un plan d'implémentation minimal avant modifications.
4.  Le frontend Next.js fonctionnel intégré au dépôt existant.
5.  Les types TypeScript basés sur les réponses réelles.
6.  Un `.env.example` actualisé si nécessaire.
7.  Des tests pertinents et les commandes pour lancer le projet.
8.  Une liste explicite des dépendances backend manquantes, sans les
    masquer par des mocks en production.
9.  Un compte rendu final indiquant les fichiers modifiés, les
    fonctionnalités terminées, les tests exécutés et les points restant
    à faire.

## 10. Phases de réalisation

### Phase A --- Maintenant

-   Inspecter le backend local et ses routes.
-   Développer le client Next.js.
-   Connecter les parcours cibles, scans, progression, findings et
    rapports à Shasec via le backend Kortex existant.
-   Ne pas intégrer Hermes.

### Phase B --- Plus tard

-   Intégrer Hermes comme moteur agentique complémentaire via une
    interface serveur contrôlée.
-   Hermes pourra utiliser HexStrike via MCP.
-   Ajouter des types de scans avancés uniquement après définition des
    autorisations, quotas et limites de coûts.
-   Conserver une interface utilisateur commune pour les scans Shasec et
    Hermes.

### Instruction finale

Travaille dans le dépôt existant, privilégie les changements minimaux et
vérifie chaque hypothèse dans le code. **La priorité est de livrer un
frontend fonctionnel connecté au backend local existant, en commençant
par Shasec. Hermes sera ajouté dans une phase distincte.**
