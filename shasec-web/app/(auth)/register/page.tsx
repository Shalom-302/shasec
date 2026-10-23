import { Suspense } from 'react';
import { AuthForm } from '@/components/auth/AuthForm';

export const metadata = { title: 'Inscription · Kortex Security' };

export default function RegisterPage() {
  return <Suspense><AuthForm mode="register" /></Suspense>;
}
