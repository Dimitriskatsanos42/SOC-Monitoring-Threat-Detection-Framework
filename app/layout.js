import './globals.css';

export const metadata = {
  title: 'SOC Monitor',
  description: 'Enterprise SOC Monitoring Dashboard'
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
