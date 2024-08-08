import { merge } from 'lodash';

export type ConfigPatch = {
  [key: string]: string | boolean | number | ConfigPatch;
};

interface UpdateAction {
  type: 'UPDATE_PATCH';
  payload: ConfigPatch;
}

interface ResetAction {
  type: 'RESET_PATCH';
}

export type ConfigAction = UpdateAction | ResetAction;

export function configPatchReducer(
  state: ConfigPatch,
  action: ConfigAction
): ConfigPatch {
  switch (action.type) {
    case 'UPDATE_PATCH':
      return structuredClone(merge(action.payload, state));
    case 'RESET_PATCH':
      return {};
  }
}

export default configPatchReducer;
