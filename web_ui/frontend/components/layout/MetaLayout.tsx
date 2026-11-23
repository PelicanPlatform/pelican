import { ReactNode } from 'react';

/**
 * MetaLayout is an empty wrapper whose only purpose is to join a metadata object
 * on a NextJS layout
 *
 * @param children
 */
const MetaLayout = ({ children }: { children: ReactNode }) => {
  return <>{children}</>;
};

export default MetaLayout;
