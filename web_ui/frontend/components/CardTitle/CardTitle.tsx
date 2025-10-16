import { Box, Typography } from '@mui/material';

interface CardTitleProps {
  title: string;
  description?: string;
}

const CardTitle = ({ title, description }: CardTitleProps) => {
  return (
    <Box>
      <Typography variant={'h6'}>{title}</Typography>
      {description && (
        <Typography variant={'subtitle2'}>{description}</Typography>
      )}
    </Box>
  );
};
export default CardTitle;
