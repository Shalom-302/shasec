// Shapes returned by the Kortex/shaapi API (backend/app/*/schema). Keep in sync
// with the Pydantic schemas; only fields the API actually returns are listed.

export type ApiEnvelope<T> = { code: number; msg: string; data: T };

export type Page<T> = {
  items: T[];
  total: number;
  page: number;
  size: number;
  total_pages: number;
};

export type Role = { name: string };

export type User = {
  id: number;
  x_id: string;
  email: string;
  firstname?: string | null;
  lastname?: string | null;
  status: boolean;
  join_time?: string;
  last_login_time?: string | null;
  roles?: Role[];
};

export type TargetType = 'website' | 'api' | 'graphql' | 'host';

export type Target = {
  id: number;
  x_id: string;
  name: string;
  url: string;
  type: TargetType;
  is_authorized: boolean;
  owner_id?: number | null;
  authorized_at?: string | null;
  terms_version?: string | null;
  created_time: string;
  updated_time?: string | null;
};

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ScanProfile = 'fast' | 'standard' | 'deep';
export type ScanBilling = 'free' | 'credits' | 'admin';

export type Scan = {
  id: number;
  x_id: string;
  target_id: number;
  status: ScanStatus;
  profile: ScanProfile;
  allow_active_exploitation: boolean;
  owner_id?: number | null;
  billing: ScanBilling;
  credits_charged: number;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
  created_time: string;
  updated_time?: string | null;
};

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Finding = {
  id: number;
  x_id: string;
  scan_id: number;
  plugin: string;
  title: string;
  severity: Severity;
  confidence: string;
  status: string;
  description?: string | null;
  evidence?: string | null;
  recommendation?: string | null;
  fingerprint?: string | null;
  created_time: string;
};

export type AIAnalysis = {
  id: number;
  scan_id: number;
  score: number;
  summary?: string | null;
  impacts?: string | null;
  recommendations?: string | null;
  provider?: string | null;
};

export type Report = {
  id: number;
  x_id: string;
  scan_id: number;
  format: 'pdf' | 'html' | 'markdown' | 'json';
  location?: string | null;
  created_time: string;
};

export type ProgressStep = { event: string; phase?: string; message?: string | null; plugin?: string | null; ts?: string };

export type Progress = {
  status: ScanStatus | string;
  percent: number;
  current_phase: string;
  phase_index: number;
  phase_total: number;
  message?: string | null;
  scanners: { total: number; done: number; running: string[] };
  steps: ProgressStep[];
};

export type CreditBalance = {
  credits: number;
  free_scans: number;
  next_expiry?: string | null;
  is_admin: boolean;
  pricing: { fast: number; standard: number; deep: number; free_profiles: string[] };
};

export type CreditGrant = {
  id: number;
  amount: number;
  remaining: number;
  kind: 'free_scan' | 'credit';
  source: 'signup' | 'voucher' | 'purchase' | 'subscription' | 'admin';
  expires_at?: string | null;
  note?: string | null;
  created_time: string;
};

export type CreditTransaction = {
  id: number;
  delta: number;
  kind: 'free_scan' | 'credit';
  reason: 'grant' | 'scan_debit' | 'scan_refund';
  scan_id?: number | null;
  note?: string | null;
  created_time: string;
};

export type Voucher = {
  id: number;
  code: string;
  credits: number;
  max_redemptions: number;
  redemption_count: number;
  valid_until?: string | null;
  credit_validity_days?: number | null;
  is_active: boolean;
  note?: string | null;
  created_time: string;
};
