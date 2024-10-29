'use client';

import { AlertDispatchContext } from '@/components/AlertProvider';
import React, { useContext } from 'react';
import { Box } from '@mui/material';
import CodeBlock from '@/components/CodeBlock';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);

  return (
    <div>
      <button
        onClick={() => {
          dispatch({
            type: 'openAlert',
            payload: {
              title: 'Response Time Slow',
              alertProps: {
                severity: 'error',
              },
              message: (
                <Box>
                  Response time is slow
                  <CodeBlock>
                    {`
                    ERROR[2024-10-24T11:32:31Z] server returned HTTP status 403 Forbidden     component="discovery manager scrape" config=origin_cache_servers discovery=http
                    ERROR[2024-10-24T11:32:46Z] server returned HTTP status 403 Forbidden     component="discovery manager scrape" config=origin_cache_servers discovery=http
                    ERROR[2024-10-24T12:49:25Z] server returned HTTP status 403 Forbidden     component="discovery manager scrape" config=origin_cache_servers discovery=http
                    ERROR[2024-10-24T12:49:40Z] server returned HTTP status 403 Forbidden     component="discovery manager scrape" config=origin_cache_servers discovery=http
                    `.replace(/^\s+/gm, '')}
                  </CodeBlock>
                </Box>
              ),
              onClose: () => dispatch({ type: 'closeAlert' }),
            },
          });
        }}
      >
        Open alert
      </button>
      <button
        onClick={() => {
          dispatch({ type: 'closeAlert' });
        }}
      >
        Close alert
      </button>
    </div>
  );
};

export default Page;
