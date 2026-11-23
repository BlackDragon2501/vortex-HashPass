import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vórtex HashPass - Contraseñas y hashes, sin límites",
  description: "Vórtex HashPass, de Vortex Company: genera contraseñas fuertes y frases de paso, evalúa su fortaleza y calcula hashes MD5, SHA-1, SHA-256 y SHA-512 de textos y archivos con Web Crypto. Gratis, sin anuncios y 100% local.",
  keywords: ["Vórtex HashPass", "generador de contraseñas", "frase de paso", "hash MD5", "SHA-256", "SHA-512", "Web Crypto", "sin anuncios"],
  authors: [{ name: "Vortex Company" }],
  icons: {
    icon:
      "data:image/svg+xml," +
      encodeURIComponent(
        `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><rect width="48" height="48" rx="10" fill="#161616"/><circle cx="24" cy="24" r="17" fill="none" stroke="#ef4444" stroke-width="3.5"/><path d="M24 10a14 14 0 1 1-9.9 4.1" fill="none" stroke="#f87171" stroke-width="3.5" stroke-linecap="round"/><path d="M24 17a7 7 0 1 0 7 7" fill="none" stroke="#f87171" stroke-width="3.5" stroke-linecap="round"/><circle cx="24" cy="24" r="3" fill="#f87171"/></svg>`
      ),
  },
  openGraph: {
    title: "Vórtex HashPass - Contraseñas y hashes, sin límites",
    description: "Vórtex HashPass, de Vortex Company: genera contraseñas fuertes y frases de paso, evalúa su fortaleza y calcula hashes MD5, SHA-1, SHA-256 y SHA-512 de textos y archivos con Web Crypto. Gratis, sin anuncios y 100% local.",
    siteName: "Vórtex HashPass - Contraseñas y hashes, sin límites",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#0f0f10",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="dark" suppressHydrationWarning>
      <body className="antialiased bg-[#0f0f10] text-[#ececf1]">{children}</body>
    </html>
  );
}
