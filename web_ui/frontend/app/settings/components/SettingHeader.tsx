import { Box, Typography } from '@mui/material';

interface SettingHeaderProps {
  title: string;
  description?: string;
}

const SettingHeader = ({ title, description }: SettingHeaderProps) => {
  return (
    <Box mb={3}>
      <Typography variant={'h5'} component={'h2'} id={title}>
        {title}
      </Typography>
      <hr />
      <Typography variant={'subtitle1'}>{description}</Typography>
    </Box>
  );
};

export default SettingHeader;
