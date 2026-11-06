import { Suspense } from 'react';
import { AuthForm } from '@/components/auth/AuthForm';

export const metadata = { title: 'Console administrateur · Kortex Defender' };

export default function AdminLoginPage() {
  return <Suspense><AuthForm mode="login" admin /></Suspense>;
}
