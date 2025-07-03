import { ReactNode } from 'react';

import { PaddedContent } from '@/components/layout';
import MetricLayout from '@/components/layout/MetricLayout';

export const metadata = {
  title: 'Metrics',
};

const Layout = ({ children }: { children: ReactNode }) => {
  return (
    <PaddedContent>
      <MetricLayout>{children}</MetricLayout>
    </PaddedContent>
  );
};

export default Layout;
