import { Alert, Box, Button } from '@mui/material';
import React, {
  Dispatch,
  SetStateAction,
  useContext,
  useEffect,
  useState,
} from 'react';
import useSWR from 'swr';

import { RegistryNamespace } from '@/index';
import CustomRegistrationField from '@/app/registry/components/CustomRegistrationField/index';
import {
  calculateKeys,
  deleteKey,
  getValue,
  populateKey,
} from '@/app/registry/components/util';
import { CustomRegistrationFieldProps } from './CustomRegistrationField';
import { alertOnError } from '@/helpers/util';
import { optionsNamespaceRegistrationFields } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { getUser } from '@/helpers/login';
import { userOwnsNamespace } from '@/components/Namespace';

interface FormProps {
  namespace?: RegistryNamespace;
  onSubmit: (data: Partial<RegistryNamespace>) => Promise<void>;
}

// The fields the owner of an Approved registration may still change. The
// registry pins every other field to its stored value for non-admin edits so
// the administrator's approval keeps meaning what was reviewed.
const OWNER_EDITABLE_APPROVED_FIELDS = [
  'admin_metadata.description',
  'admin_metadata.site_name',
  'admin_metadata.institution',
  'admin_metadata.security_contact_user_id',
];

const onChange = (
  name: string,
  value: string | number | boolean | null | undefined,
  setData: Dispatch<SetStateAction<Partial<RegistryNamespace | undefined>>>
) => {
  setData((prevData) => {
    // If the value is undefined delete this key from the data dictionary
    if (value === undefined) {
      let newData = structuredClone(prevData);
      deleteKey(newData, calculateKeys(name));
      return newData;
    }

    // Otherwise populate the key in the data dictionary
    let newData = structuredClone(prevData);
    populateKey(newData, calculateKeys(name), value);
    return newData;
  });
};

const Form = ({ namespace, onSubmit }: FormProps) => {
  const dispatch = useContext(AlertDispatchContext);

  const [formNamespace, setFormNamespace] = useState<
    Partial<RegistryNamespace> | undefined
  >(namespace || {});

  const { data: fields, error } = useSWR<
    Omit<CustomRegistrationFieldProps, 'onChange'>[] | undefined
  >(
    'optionsNamespaceRegistrationFields',
    async () => {
      const response = await alertOnError(
        optionsNamespaceRegistrationFields,
        "Couldn't fetch registration fields",
        dispatch
      );
      if (response) {
        return await response.json();
      }
    },
    { fallbackData: [] }
  );

  const { data: user } = useSWR('getUser', getUser);

  // A non-admin editing an Approved registration can only change the
  // descriptive fields; treat an unknown role as non-admin until it loads
  const restrictedEdit =
    namespace?.admin_metadata?.status === 'Approved' && user?.role !== 'admin';

  // Auto-fill the security contact when the current user is the operator of
  // this registration and no contact has been set yet
  useEffect(() => {
    if (
      user === undefined ||
      namespace?.admin_metadata?.security_contact_user_id
    ) {
      return;
    }

    // The current user is known to be the operator when either:
    //  - the request came from their Origin/Cache web UI (fromUrl param), or
    //  - they already own the registration, e.g. right after claiming it via
    //    the completion link the server logs, which carries no fromUrl
    const fromUrl = new URL(window.location.href).searchParams.get('fromUrl');
    const ownsRegistration =
      namespace !== undefined && userOwnsNamespace(user, namespace);

    if (fromUrl || ownsRegistration) {
      // Prefer the stable Pelican user ID over the login username so the
      // contact reference survives identity-provider changes
      onChange(
        'admin_metadata.security_contact_user_id',
        user?.user_id || user?.user,
        setFormNamespace
      );
    }
  }, [user, setFormNamespace, namespace]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();

        if (!formNamespace) {
          return;
        }
        onSubmit(formNamespace);
      }}
    >
      {error && (
        <Alert severity={'error'}>{error.message}; Retry is automatic.</Alert>
      )}
      {restrictedEdit && (
        <Alert severity={'info'} sx={{ mb: 2 }}>
          This registration is approved. You can update its description, site
          name, institution, and security contact; the remaining fields are
          locked and can only be changed by a registry administrator.
        </Alert>
      )}
      {fields &&
        fields.map((field, index) => {
          return (
            <Box key={field.name} pt={index == 0 ? 0 : 2}>
              <CustomRegistrationField
                onChange={(value: string | number | boolean | null) =>
                  onChange(field.name, value, setFormNamespace)
                }
                value={getValue(formNamespace, calculateKeys(field.name))}
                disabled={
                  restrictedEdit &&
                  !OWNER_EDITABLE_APPROVED_FIELDS.includes(field.name)
                }
                {...field}
              />
            </Box>
          );
        })}
      <Box pt={2}>
        <Button type={'submit'} variant={'contained'}>
          Submit
        </Button>
      </Box>
    </form>
  );
};

export default Form;
