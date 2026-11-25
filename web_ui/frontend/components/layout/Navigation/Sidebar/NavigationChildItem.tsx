'use client';

import { usePathname } from 'next/navigation';

import {
  StaticNavigationChildItemProps,
  isActive,
} from '@/components/layout/Navigation';
import RailItemButton from '@/components/layout/Navigation/Sidebar/RailItemButton';
import { evaluateOrReturn } from '@/helpers/util';

/**
 * A leaf destination in the rail. Kept apart from NavigationItem so the
 * submenu can render its children through the same row without the two
 * modules importing each other.
 */
export const NavigationChildItem = ({
  title,
  href,
  icon,
  exactMatch,
}: StaticNavigationChildItemProps) => {
  const pathname = usePathname();

  const label = evaluateOrReturn(title);
  const path = evaluateOrReturn(href);

  return (
    <RailItemButton
      label={label}
      icon={icon}
      href={path}
      active={isActive(path, pathname, exactMatch)}
    />
  );
};
