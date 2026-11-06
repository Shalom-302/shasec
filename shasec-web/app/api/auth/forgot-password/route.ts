import type { NextRequest } from 'next/server';
import { forgotPassword } from '@/lib/server/auth-route';

export async function POST(req: NextRequest) {
  return forgotPassword(req);
}
