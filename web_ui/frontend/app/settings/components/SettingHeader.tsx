import { Box, BoxProps, Typography } from '@mui/material';

interface SettingHeaderProps extends BoxProps {
  title: string;
  action?: React.ReactNode;
  description?: string;
}

const SettingHeader = ({
  title,
  action,
  description,
  ...props
}: SettingHeaderProps) => {
  return (
    <Box mb={3} {...props}>
      <Box
        display={'flex'}
        flexDirection={'row'}
        justifyContent={'space-between'}
      >
        <Typography variant={'h5'} component={'h2'} id={title} my={'auto'}>
          {title}
        </Typography>
        {action && (
          <Box display={'flex'} flexDirection={'row'}>
            {action}
          </Box>
        )}
      </Box>
      <hr />
      <Typography variant={'subtitle1'}>{description}</Typography>
    </Box>
  );
};

export default SettingHeader;
