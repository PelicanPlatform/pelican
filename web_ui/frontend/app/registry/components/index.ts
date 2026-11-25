import { RegistryNamespace } from '@/index';

// The kind of registration a form page creates or edits. The registry serves
// one field list for all three, but only a namespace prefix may carry an auth
// state, so the form needs to know which one it is showing
export type RegistrationKind = 'namespace' | 'origin' | 'cache';

export interface NamespaceFormPage {
  kind: RegistrationKind;
  update: (data: Partial<RegistryNamespace>) => Promise<Response>;
}
