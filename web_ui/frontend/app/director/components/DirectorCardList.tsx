'use client';

import React, { useMemo, useState } from 'react';
import {
  Box,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from '@mui/material';
import semver from 'semver';

import { DirectorCard, DirectorCardProps } from './';
import { BooleanToggleButton, CardList } from '@/components';
import useFuse from '@/helpers/useFuse';
import serverHasError from '@/helpers/serverHasError';

interface DirectorCardListProps {
  data: Partial<DirectorCardProps>[];
  cardProps: Partial<DirectorCardProps>;
}

export function DirectorCardList({ data, cardProps }: DirectorCardListProps) {
  const [search, setSearch] = useState<string>('');
  const [pelicanServer, setPelicanServer] = useState<boolean | undefined>(
    undefined
  );
  const [serverError, setServerError] = useState<boolean | undefined>(
    undefined
  );
  const [serverDowntime, setServerDowntime] = useState<boolean | undefined>(
    undefined
  );
  const [serverVersions, setServerVersions] = useState<string[]>([]);

  const searchedData = useFuse<Partial<DirectorCardProps>>(data, search);

  const filteredData = useMemo(() => {
    let filteredData = structuredClone(searchedData);
    if (pelicanServer != undefined) {
      filteredData = filteredData.filter(
        (d) => d?.server?.fromTopology != pelicanServer
      );
    }
    if (serverError != undefined) {
      filteredData = filteredData.filter(
        (d) => serverHasError(d?.server) == serverError
      );
    }
    if (serverDowntime != undefined) {
      filteredData = filteredData.filter(
        (d) => d?.server?.filtered == serverDowntime
      );
    }
    if (serverVersions.length > 0) {
      filteredData = filteredData.filter(
        (d) => d?.server?.version && serverVersions.includes(d.server.version)
      );
    }
    return filteredData;
  }, [
    searchedData,
    search,
    serverError,
    pelicanServer,
    serverDowntime,
    serverVersions,
  ]);

  const allServerVersions = useMemo(() => {
    const semverVersions = new Set<string>();
    const nonSemverVersions = new Set<string>();
    data.forEach((d) => {
      if (d.server?.version && semver.valid(d.server.version) !== null) {
        semverVersions.add(d.server.version);
      } else if (d.server?.version && semver.valid(d.server.version) === null) {
        nonSemverVersions.add(d.server.version);
      }
    });

    return [
      ...semver.sort([...semverVersions]).reverse(),
      ...[...nonSemverVersions].sort().reverse(),
    ];
  }, [data]);

  return (
    <Box>
      <Box sx={{ pb: 1 }}>
        <Grid container spacing={1} pt={1}>
          <Grid>
            <TextField
              size={'small'}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              label='Search'
            />
          </Grid>
          <Grid>
            <FormControl sx={{ width: 200 }} size={'small'}>
              <InputLabel id={'server-version-select-label'}>
                Server Version
              </InputLabel>
              <Select
                multiple
                id={'server-version-select'}
                value={serverVersions}
                onChange={(e) => setServerVersions(e.target.value as string[])}
                labelId={'server-version-select-label'}
                label={'Server Version'}
              >
                {allServerVersions.map((version) => (
                  <MenuItem key={version} value={version}>
                    {version}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>
        <Grid container spacing={1} pt={1}>
          <Grid>
            <BooleanToggleButton
              label={'Is Pelican Server'}
              value={pelicanServer}
              onChange={setPelicanServer}
            />
          </Grid>
          <Grid>
            <BooleanToggleButton
              label={'Has Error'}
              value={serverError}
              onChange={setServerError}
            />
          </Grid>
          <Grid>
            <BooleanToggleButton
              label={'In Downtime'}
              value={serverDowntime}
              onChange={setServerDowntime}
            />
          </Grid>
        </Grid>
      </Box>
      <CardList
        data={filteredData}
        Card={DirectorCard}
        cardProps={cardProps}
        keyGetter={(o) => o.server.name}
      />
    </Box>
  );
}

export default DirectorCardList;
