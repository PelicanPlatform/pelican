import { grey } from '@mui/material/colors';
import { Box, BoxProps, styled } from '@mui/material';

const Code = styled(Box)<BoxProps>(({ theme }) => ({
  backgroundColor: grey[100],
  padding: `${theme.spacing(1)} ${theme.spacing(2)}`,
  borderRadius: theme.shape.borderRadius,
  fontFamily: 'monospace',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  overflowX: 'auto',
  fontSize: '.8rem',
}));

export default Code;
