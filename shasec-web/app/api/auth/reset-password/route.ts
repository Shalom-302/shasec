import type { NextRequest } from 'next/server';
import { resetPassword } from '@/lib/server/auth-route';

export async function POST(req: NextRequest) {
  return resetPassword(req);
}
