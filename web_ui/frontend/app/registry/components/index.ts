import { RegistryNamespace } from '@/index';

export interface NamespaceFormPage {
  update: (data: Partial<RegistryNamespace>) => Promise<Response>;
}
