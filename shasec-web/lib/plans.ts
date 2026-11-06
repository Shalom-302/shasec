// Commercial offers, shown on the landing page and the credits page.
// Display only: prices and credits are decided server-side (PAYMENT_PACKS);
// `pack` links a card to the API pack id that the buy button sends.
export const PLANS = [
  {
    name: 'Free', tag: 'Découverte', price: '0 FCFA', note: 'Les 3 scans gratuits sont utilisables une seule fois par compte.',
    items: ['3 scans de découverte gratuits par compte', 'Résultats essentiels dans le dashboard', 'Aucun rapport téléchargeable', 'Aucune alerte de surveillance'],
  },
  {
    name: 'Essentiel', pack: 'essentiel', tag: 'Pour essayer', price: '1 000 FCFA', note: 'Les crédits achetés n’expirent pas.',
    items: ['10 crédits Kortex Defender', 'Rapports de sécurité détaillés', 'Idéal pour un premier audit complet'],
  },
  {
    name: 'Starter', pack: 'starter', tag: 'Paiement à l’utilisation', price: '2 000 FCFA', note: 'Les crédits achetés n’expirent pas.',
    items: ['20 crédits Kortex Defender', 'Rapports de sécurité détaillés', 'Alertes sur les nouvelles vulnérabilités', 'Notifications dashboard et email'],
  },
  {
    name: 'Premium', pack: 'premium', tag: 'Offre recommandée', price: '5 000 FCFA / mois', highlight: true,
    note: 'Crédits valables 30 jours à partir du paiement (renouvellement manuel).',
    items: ['60 crédits mensuels', 'Surveillance planifiée d’un domaine', 'Rapports détaillés et historique', 'Alertes WhatsApp, email et dashboard', 'Priorité dans la file de scans'],
  },
  {
    name: 'Premium Plus', tag: 'Sur devis', price: 'Tarif personnalisé', note: 'Chaque devis précise le périmètre, les quotas et le support.',
    items: ['Plusieurs domaines ou applications', 'Quotas de crédits personnalisés', 'Audits avancés selon le périmètre autorisé', 'Collaboration multi-utilisateurs'],
  },
];
