import { Config, ParameterInputProps } from '@/components/Config/index';
import React, { useState } from 'react';
import { Box, Link, Typography } from '@mui/material';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { isConfig, sortConfig } from '@/app/config/util';

interface TableOfContentsProps {
  id: string[];
  name: string;
  value: Config | ParameterInputProps;
  level: number;
}

export function TableOfContents({
  id,
  name,
  value,
  level = 1,
}: TableOfContentsProps) {
  const [open, setOpen] = useState(false);

  if (name != '') {
    id = [...id, name];
  }

  let subContents = undefined;
  if (isConfig(value)) {
    let subValues = Object.entries(value);
    subValues.sort(sortConfig);
    subContents = subValues.map(([key, value]) => {
      return (
        <TableOfContents
          id={id}
          key={key}
          name={key}
          value={value}
          level={level + 1}
        />
      );
    });
  }

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
        href={subContents ? undefined : `#${id.join('-')}`}
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
          {name}
        </Typography>
        {subContents ? open ? <ArrowDropUp /> : <ArrowDropDown /> : undefined}
      </Link>
    </Box>
  );

  return (
    <>
      {name ? headerPointer : undefined}
      {subContents && level != 1 ? (
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
