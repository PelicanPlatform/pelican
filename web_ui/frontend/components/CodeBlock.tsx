import { stackoverflowLight } from 'react-syntax-highlighter/dist/cjs/styles/hljs';
import SyntaxHighlighter from 'react-syntax-highlighter';
import { Box } from '@mui/material';

/**
 * CodeBlock component
 * Copy onClick and darken onHover
 * @param children
 * @constructor
 */
export const CodeBlock = ({children}: {children: string | string[]}) => {
  return <Box>
    <SyntaxHighlighter
      style={stackoverflowLight}
      wrapLines
      onClick={() => {
        navigator.clipboard.writeText(children.toString());
      }}
    >
      {children}
    </SyntaxHighlighter>
  </Box>
}

export default CodeBlock;
