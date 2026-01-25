import './globals.css';
import { Inter } from 'next/font/google';
import { ThemeProvider } from '@/components/theme/theme-provider';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

export const metadata = {
  title: '4postle - Advanced Vulnerability Scanner',
  description: 'Professional web-based vulnerability assessment and security scanning platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning className="bg-black">
      <body className={`${inter.variable} font-mono bg-black text-green-400 antialiased`} style={{backgroundColor: '#000000', color: '#22c55e'}}>
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
