import { ReactNode } from 'react';

import { PaddedContent } from '@/components/layout';
import MetricLayout from '@/components/layout/MetricLayout';

const Layout = ({ children }: { children: ReactNode }) => {
  return (
    <PaddedContent>
      <MetricLayout>{children}</MetricLayout>
    </PaddedContent>
  );
};

export default Layout;
