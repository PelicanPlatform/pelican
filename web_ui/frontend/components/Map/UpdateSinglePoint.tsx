/**
 * A form element that allows the user to pick a latitude and longitude
 */
import { DefaultMap } from '@/components/Map';
import { Marker, NavigationControl } from 'react-map-gl/maplibre';
import { FmdGood } from '@mui/icons-material';
import React, { useCallback } from 'react';
import { LngLat } from 'maplibre-gl';

interface LatitudeLongitudePickerProps {
  latitude: number;
  longitude: number;
  setLatitude: (latitude: number) => void;
  setLongitude: (longitude: number) => void;
  zoom?: number;
}

const LatitudeLongitudePicker = ({
  latitude,
  longitude,
  setLatitude,
  setLongitude,
  zoom
}: LatitudeLongitudePickerProps) => {

  const updateLatLng = useCallback((lngLat: LngLat) => {
    setLatitude(parseFloat(lngLat.lat.toFixed(5)));
    setLongitude(parseFloat(lngLat.lng.toFixed(5)));
  }, []);

  const tempLongitude = Number.isNaN(longitude) ? 0 : longitude
  const tempLatitude = Number.isNaN(latitude) ? 0 : latitude

  return (
    <DefaultMap
      initialViewState={{
        longitude: tempLongitude,
        latitude: tempLatitude,
        zoom: zoom || 0,
      }}
      scrollZoom={false}
      style={{ width: '100%', height: '100%' }}
      onClick={(e) => updateLatLng(e.lngLat)}
    >
      <NavigationControl />
      <Marker
        longitude={tempLongitude}
        latitude={tempLatitude}
        anchor='bottom'
        draggable={true}
        onDrag={(e) => updateLatLng(e.lngLat as LngLat)}
      >
        <FmdGood />
      </Marker>
    </DefaultMap>
  );
}

export default LatitudeLongitudePicker
