import { Box, BoxProps, Typography } from '@mui/material';

interface SettingHeaderProps extends BoxProps {
  title: string;
  description?: string;
}

const SettingHeader = ({ title, description, ...props }: SettingHeaderProps) => {
  return (
    <Box mb={3} {...props}>
      <Typography variant={'h5'} component={'h2'} id={title}>
        {title}
      </Typography>
      <hr />
      <Typography variant={'subtitle1'}>{description}</Typography>
    </Box>
  );
};

export default SettingHeader;
