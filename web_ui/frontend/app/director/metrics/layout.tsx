import { GraphProvider } from '@/app/origin/metrics/components/GraphContext';
import { ReactNode } from 'react';
import { GraphOverlay } from '@/app/origin/metrics/components/GraphOverlay';
import { PaddedContent } from '@/components/layout';

const Layout = ({ children } : {children: ReactNode}) => {
  return (
    <PaddedContent>
      <GraphProvider>
        <GraphOverlay>
          {children}
        </GraphOverlay>
      </GraphProvider>
    </PaddedContent>
  )
}

export default Layout;
