// Terms of use shown at /terms and accepted per target before scanning.
// Bump TERMS_VERSION together with settings.TERMS_VERSION (backend/core/conf.py)
// whenever the text changes: older acceptances then no longer authorize new scans.
export const TERMS_VERSION = '2026-10-23';

export const TERMS: { title: string; body: string[] }[] = [
  {
    title: '1. Objet',
    body: [
      'Kortex Security fournit un service d’audit de sécurité automatisé de sites web, d’API et d’hôtes exposés sur Internet. Ces conditions encadrent l’utilisation de la plateforme.',
    ],
  },
  {
    title: '2. Autorisation préalable obligatoire',
    body: [
      'Vous ne pouvez lancer un scan que sur une cible dont vous êtes propriétaire, ou pour laquelle vous disposez d’une autorisation écrite, préalable et explicite de son propriétaire couvrant ce type de test.',
      'Pour chaque cible, vous attestez disposer de cette autorisation. Cette attestation est horodatée et conservée avec votre identifiant et votre adresse IP.',
      'Tester un système sans autorisation est interdit et peut constituer une infraction pénale (notamment l’accès ou le maintien frauduleux dans un système de traitement automatisé de données).',
    ],
  },
  {
    title: '3. Nature des tests',
    body: [
      'Les scans réalisés par les comptes clients sont non destructifs : reconnaissance, détection de configurations faibles et de vulnérabilités connues. Aucune exploitation active ni modification de données n’est effectuée.',
      'Un scan génère du trafic vers la cible et peut être visible dans ses journaux ou déclencher ses systèmes de détection. Prévenez vos équipes et hébergeurs si nécessaire.',
    ],
  },
  {
    title: '4. Responsabilité de l’utilisateur',
    body: [
      'Vous êtes seul responsable du choix des cibles, de la véracité de votre attestation et de l’usage fait des résultats.',
      'Vous vous engagez à garantir Kortex Security contre toute réclamation résultant d’un scan lancé sans autorisation valable.',
    ],
  },
  {
    title: '5. Suspension',
    body: [
      'Kortex Security peut suspendre un compte, révoquer l’autorisation d’une cible ou refuser un scan en cas de doute sur la légitimité d’une demande, de signalement d’un tiers ou d’usage abusif, sans remboursement des crédits consommés à cette occasion.',
    ],
  },
  {
    title: '6. Crédits',
    body: [
      'Les scans sont décomptés en crédits selon le profil choisi. Un scan qui échoue pour une raison technique est recrédité. Les scans de découverte gratuits ne donnent pas accès aux rapports téléchargeables.',
    ],
  },
  {
    title: '7. Confidentialité des résultats',
    body: [
      'Les résultats de vos scans ne sont accessibles qu’à votre compte et aux administrateurs de la plateforme pour les besoins du support et de la sécurité du service.',
    ],
  },
];
