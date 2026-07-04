import { RegistryNamespace } from '@/index';
import Card, { CardProps } from './Card';
import CreateNamespaceCard from './CreateNamespaceCard';
import CardSkeleton from './CardSkeleton';
import PendingCard, { PendingCardProps } from './PendingCard';
import IncompleteCard from './IncompleteCard';
import NamespaceCardList from './NamespaceCardList';
import NamespaceIcon from './NamespaceIcon';

export {
  Card,
  NamespaceCardList,
  CreateNamespaceCard,
  CardSkeleton,
  PendingCard,
  IncompleteCard,
  NamespaceIcon,
};

export type RegistrationStatus =
  | 'Incomplete'
  | 'Pending'
  | 'Approved'
  | 'Denied'
  | 'Unknown';

// Human-facing labels for registration statuses
export const getStatusDisplayName = (status: RegistrationStatus): string => {
  switch (status) {
    case 'Pending':
      return 'Pending (Ready to review)';
    default:
      return status;
  }
};

export interface NamespaceAdminMetadata {
  user_id: string;
  description: string;
  site_name: string;
  institution: string;
  security_contact_user_id: string;
  status: RegistrationStatus;
  approver_id: number;
  approved_at: string;
  created_at: string;
  updated_at: string;
}

export interface FlatObject {
  [key: string]: Exclude<any, object>;
}

export type NamespaceCardProps = CardProps & PendingCardProps;

export const getServerType = (namespace: RegistryNamespace) => {
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
