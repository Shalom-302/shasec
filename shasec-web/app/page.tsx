import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export default function Home() {
  redirect(cookies().get('kx_at')?.value ? '/dashboard' : '/login');
}
