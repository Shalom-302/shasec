import { Suspense } from 'react';
import { AuthForm } from '@/components/auth/AuthForm';

export const metadata = { title: 'Connexion · Kortex Defender' };

export default function LoginPage() {
  return <Suspense><AuthForm mode="login" /></Suspense>;
}
