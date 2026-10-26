import type { NextRequest } from 'next/server';
import { verifyOtp } from '@/lib/server/auth-route';

export async function POST(req: NextRequest) {
  return verifyOtp(req);
}
