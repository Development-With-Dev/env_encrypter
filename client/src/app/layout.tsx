import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure Access Protocol",
  description: "End-to-end encrypted configuration sharing.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full overflow-hidden">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800;900&display=swap" rel="stylesheet" />
      </head>
      <body className="antialiased h-full w-full bg-black text-white selection:bg-white selection:text-black overflow-hidden no-scrollbar">
        <main className="h-full w-full flex flex-col overflow-hidden">
          {children}
        </main>
      </body>
    </html>
  );
}
