import { Namespace } from '@/index';
import Card from './Card';
import CreateNamespaceCard from './CreateNamespaceCard';
import CardSkeleton from './CardSkeleton';
import PendingCard from './PendingCard';
import NamespaceCardList from './NamespaceCardList';
import NamespaceIcon from './NamespaceIcon';

export {
  Card,
  NamespaceCardList,
  CreateNamespaceCard,
  CardSkeleton,
  PendingCard,
  NamespaceIcon,
};

import { PendingCardProps } from './PendingCard';
import { CardProps } from './Card';

export interface NamespaceAdminMetadata {
  user_id: string;
  description: string;
  site_name: string;
  institution: string;
  security_contact_user_id: string;
  status: 'Pending' | 'Approved' | 'Denied' | 'Unknown';
  approver_id: number;
  approved_at: string;
  created_at: string;
  updated_at: string;
}

export interface FlatObject {
  [key: string]: Exclude<any, object>;
}

export type NamespaceCardProps = CardProps & PendingCardProps;

export const getServerType = (namespace: Namespace) => {
  // If the namespace is empty the value is undefined
  if (namespace?.prefix == null || namespace.prefix == '') {
    return '';
  }

  // If the namespace prefix starts with /cache, it is a cache server
  if (namespace.prefix.startsWith('/caches/')) {
    return 'cache';
  }

  // Otherwise it is an origin server
  return 'origin';
};
