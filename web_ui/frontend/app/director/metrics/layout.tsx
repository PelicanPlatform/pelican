import { ReactNode } from 'react';
import { PaddedContent } from '@/components/layout';
import dynamic from 'next/dynamic';

const GraphProvider = dynamic(
  () => import('../../../components/graphs/GraphContext'),
  { ssr: false }
);

const GraphOverlay = dynamic(
  () => import('../../../components/graphs/GraphOverlay'),
  { ssr: false }
);

const Layout = ({ children }: { children: ReactNode }) => {
  return (
    <PaddedContent>
      <GraphProvider>
        <GraphOverlay>{children}</GraphOverlay>
      </GraphProvider>
    </PaddedContent>
  );
};

export default Layout;
