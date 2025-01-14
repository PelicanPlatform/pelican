/**
 * A form element that allows the user to pick a latitude and longitude
 */
import { DefaultMap } from '@/components/Map';
import { Box } from '@mui/material';

interface LatitudeLongitudePickerProps {
  latitude: number;
  longitude: number;
  setLatitude: (latitude: number) => void;
  setLongitude: (longitude: number) => void;
}

const LatitudeLongitudePicker = ({
  latitude,
  longitude,
  setLatitude,
  setLongitude,
}: LatitudeLongitudePickerProps) => {
  return (
    <div>
      <Box>
        <DefaultMap />
      </Box>
      <label>
        Latitude:
        <input
          type="number"
          value={latitude}
          onChange={(e) => setLatitude(parseFloat(e.target.value))}
        />
      </label>
      <label>
        Longitude:
        <input
          type="number"
          value={longitude}
          onChange={(e) => setLongitude(parseFloat(e.target.value))}
        />
      </label>
    </div>
  );
}

export default LatitudeLongitudePicker
