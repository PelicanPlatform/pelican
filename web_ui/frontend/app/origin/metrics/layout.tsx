import { GraphProvider } from '@/app/origin/metrics/components/GraphContext';
import { ReactNode } from 'react';
import { GraphOverlay } from '@/app/origin/metrics/components/GraphOverlay';

const Layout = ({ children } : {children: ReactNode}) => {
  return (
    <GraphProvider>
      <GraphOverlay>
        {children}
      </GraphOverlay>
    </GraphProvider>
  )
}

export default Layout;
