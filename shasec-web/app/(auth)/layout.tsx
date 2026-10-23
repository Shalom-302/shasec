import Link from 'next/link';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-10">
      <Link href="/" className="mb-8 text-2xl font-bold tracking-tight">
        Kortex <span className="text-kx-accent">Security</span>
      </Link>
      <div className="w-full max-w-sm">{children}</div>
    </div>
  );
}
