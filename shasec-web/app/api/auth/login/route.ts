import type { NextRequest } from 'next/server';
import { authenticate } from '@/lib/server/auth-route';

export async function POST(req: NextRequest) {
  return authenticate(req, 'login');
}
