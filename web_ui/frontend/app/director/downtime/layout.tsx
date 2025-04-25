import Main from '@/components/layout/Main';
import { PaddedContent } from '@/components/layout';

export const metadata = {
  title: 'Federation Downtime',
  description: 'Federation downtime view',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <PaddedContent>{children}</PaddedContent>;
}
