// Public relay for MoneyFusion's payment notification -> API. The API only reads
// the token from it and verifies the payment with MoneyFusion before crediting,
// so nothing here needs to be trusted. Always 200 so the aggregator stops retrying.
import { NextRequest, NextResponse } from 'next/server';
import { apiFetch, clientIp } from '@/lib/server/backend';

export async function POST(req: NextRequest, { params }: { params: { secret: string } }) {
  const body = await req.text();
  if (body.length > 20_000) return NextResponse.json({ status: 'ignored' });
  const res = await apiFetch(`/payments/webhook/${encodeURIComponent(params.secret)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    ip: clientIp(req),
  }).catch(() => null);
  if (res?.status === 404) return NextResponse.json({ msg: 'Not Found' }, { status: 404 });
  return NextResponse.json({ status: 'received' });
}
