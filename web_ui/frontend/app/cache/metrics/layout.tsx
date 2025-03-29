import { ReactNode } from 'react';
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
    <GraphProvider>
      <GraphOverlay>{children}</GraphOverlay>
    </GraphProvider>
  );
};

export default Layout;
