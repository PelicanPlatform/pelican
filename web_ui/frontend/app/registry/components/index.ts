import { Alert as AlertType, Namespace } from '@/index';

export interface NamespaceFormPage {
  update: (data: Partial<Namespace>) => Promise<AlertType | undefined>;
}
