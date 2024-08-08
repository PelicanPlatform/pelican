import {
  Config,
  ParameterInputProps,
  ParameterMetadata,
  ParameterMetadataRecord,
} from '@/components/configuration/index';
import React, { useMemo, useState } from 'react';
import { Box, Link, Typography } from '@mui/material';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import {
  ExpandedObject,
  expandObject,
  isParameterMetadata,
  sortMetadata,
} from '@/app/config/util';

export interface TableOfContentsProps {
  metadata: ParameterMetadataRecord;
}

export const TableOfContents = ({ metadata }: TableOfContentsProps) => {
  const expandedMetadata = expandObject(metadata);
  return <TableOfContentsHelper name={[]} metadata={expandedMetadata} />;
};

interface TableOfContentsHelperProps {
  name: string[];
  metadata: ExpandedObject<ParameterMetadata> | ParameterMetadata;
}

export function TableOfContentsHelper({
  name,
  metadata,
}: TableOfContentsHelperProps) {
  const [open, setOpen] = useState(false);

  let subContents = undefined;
  // If we arrived at a leaf containing the metadata for a parameter, display the field
  if (!isParameterMetadata(metadata)) {
    let subValues = Object.entries(metadata as ParameterMetadataRecord);
    subValues.sort(sortMetadata);
    subContents = subValues.map(([key, metadata]) => {
      const childName = [...name, key];
      return (
        <TableOfContentsHelper key={key} name={childName} metadata={metadata} />
      );
    });
  }

  // Check if this is the root element, if so we want to return the children directly
  if (name.length == 0) {
    return subContents;
  }

  const level = name.length;
  let headerPointer = (
    <Box
      sx={{
        '&:hover': {
          backgroundColor: 'primary.light',
        },
        borderRadius: 1,
        paddingX: '5px',
        paddingLeft: 0 + 5 * level + 'px',
      }}
    >
      <Link
        href={subContents ? undefined : `#${name.join('-')}`}
        sx={{
          cursor: 'pointer',
          textDecoration: 'none',
          color: 'black',
          display: 'flex',
          flexDirection: 'row',
          justifyContent: 'space-between',
        }}
        onClick={() => {
          setOpen(!open);
        }}
      >
        <Typography
          style={{
            fontSize: 20 - 2 * level + 'px',
            fontWeight: subContents ? '600' : 'normal',
          }}
        >
          {name[name.length - 1]}
        </Typography>
        {subContents ? open ? <ArrowDropUp /> : <ArrowDropDown /> : undefined}
      </Link>
    </Box>
  );

  return (
    <>
      {name ? headerPointer : undefined}
      {subContents ? (
        <Box
          sx={{
            display: open ? 'block' : 'none',
            cursor: 'pointer',
          }}
        >
          {subContents}
        </Box>
      ) : (
        subContents
      )}
    </>
  );
}

export default TableOfContents;
