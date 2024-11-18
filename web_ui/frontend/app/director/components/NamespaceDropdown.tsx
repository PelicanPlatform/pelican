import { Dropdown, InformationSpan, InformationSpanHeader } from '@/components';
import { Box, Grid } from '@mui/material';
import React, { Fragment } from 'react';
import { Namespace, ServerDetailed } from '@/types';
import { NamespaceCapabilitiesTable } from '@/components/NamespaceCapabilitiesTable';

interface NamespaceDropdownProps {
  namespace: Namespace;
  servers?: ServerDetailed[];
  transition: boolean;
}

export const NamespaceDropdown = ({
  namespace,
  servers,
  transition
}: NamespaceDropdownProps) => {
  return (
    <>
      <Dropdown transition={transition} flexDirection={'column'}>
        <Grid container spacing={1}>
          <Grid item xs={12} md={12}>
            <InformationSpan name={'Path'} value={namespace.path} />
            <InformationSpanHeader title={'Token Generation'} />
            {namespace.tokenGeneration?.map((tg) =>
              <Fragment key={tg.issuer}>
                <InformationSpan indent={1} name={'Issuer'} value={tg.issuer} />
                <InformationSpan indent={2} name={'Strategy'} value={tg.strategy} />
                <InformationSpan indent={2} name={'VaultServer'} value={tg.vaultServer} />
                <InformationSpan indent={2} name={'Max Scope Depth'} value={tg.maxScopeDepth.toString()} />
              </Fragment>
            )}
            <InformationSpanHeader title={'Token Issuer'} />
            {namespace.tokenIssuer?.map((ti) =>
              <Fragment key={ti.issuer}>
                <InformationSpan indent={1} name={'Issuer'} value={ti.issuer} />
                <InformationSpanHeader indent={2} title={"Base Paths"} />
                {ti.basePaths.map((bp) =>
                  <InformationSpan key={bp} indent={3} name={'Base Path'} value={bp} />
                )}
                { ti.restrictedPaths && (
                  <>
                    <InformationSpanHeader indent={2} title={"Restricted Paths"} />
                    {ti.restrictedPaths?.map((rp) =>
                      <InformationSpan key={rp} indent={3} name={'Restricted Path'} value={rp} />
                    )}
                  </>
                  )
                }
              </Fragment>
            )}
          </Grid>
        </Grid>
        <Box sx={{ my: 1 }}>
          <NamespaceCapabilitiesTable namespace={namespace} servers={servers} />
        </Box>
      </Dropdown>
    </>
  );
};
