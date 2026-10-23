// Commercial offers, shown on the landing page and the credits page.
// Display only: credits are granted server-side (vouchers today, payments later).
export const PLANS = [
  {
    name: 'Free', tag: 'Découverte', price: '0 FCFA', note: 'Les 3 scans gratuits sont utilisables une seule fois par compte.',
    items: ['3 scans de découverte gratuits par compte', 'Résultats essentiels dans le dashboard', 'Aucun rapport téléchargeable', 'Aucune alerte de surveillance'],
  },
  {
    name: 'Starter', tag: 'Paiement à l’utilisation', price: '2 000 FCFA', note: 'Les crédits achetés n’expirent pas.',
    items: ['20 crédits Kortex Security', 'Rapports de sécurité détaillés', 'Alertes sur les nouvelles vulnérabilités', 'Notifications dashboard et email'],
  },
  {
    name: 'Premium', tag: 'Offre recommandée', price: '5 000 FCFA / mois', highlight: true,
    note: 'Crédits mensuels valables pendant le cycle d’abonnement.',
    items: ['60 crédits mensuels', 'Surveillance planifiée d’un domaine', 'Rapports détaillés et historique', 'Alertes WhatsApp, email et dashboard', 'Priorité dans la file de scans'],
  },
  {
    name: 'Premium Plus', tag: 'Sur devis', price: 'Tarif personnalisé', note: 'Chaque devis précise le périmètre, les quotas et le support.',
    items: ['Plusieurs domaines ou applications', 'Quotas de crédits personnalisés', 'Audits avancés selon le périmètre autorisé', 'Collaboration multi-utilisateurs'],
  },
];
