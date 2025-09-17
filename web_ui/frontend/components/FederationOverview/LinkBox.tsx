import Link from 'next/link';
import { Box, Typography } from '@mui/material';
import LaunchIcon from '@mui/icons-material/Launch';

const LinkBox = ({ href, text }: { href: string; text: string }) => {
  return (
    <Link href={href}>
      <Box
        p={1}
        px={2}
        display={'flex'}
        flexDirection={'row'}
        bgcolor={'info.light'}
        borderRadius={2}
        mb={1}
      >
        <Typography sx={{ pb: 0 }}>{text}</Typography>
        <Box ml={'auto'} my={'auto'} display={'flex'}>
          <LaunchIcon />
        </Box>
      </Box>
    </Link>
  );
};

export default LinkBox;
