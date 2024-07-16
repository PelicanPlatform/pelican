import React from "react"
import Map, { AttributionControl, LngLatLike, Marker } from 'react-map-gl/maplibre';
import {FmdGood} from "@mui/icons-material";

import 'maplibre-gl/dist/maplibre-gl.css';

export interface SinglePointMapProps {
  point: {lng: number, lat: number},
  zoom?: number
}

export const SinglePointMap = ({point, zoom} : SinglePointMapProps) => {
  return (
    <Map
      initialViewState={{
        longitude: point.lng,
        latitude: point.lat,
        zoom: zoom || 1
      }}
      scrollZoom={false}
      style={{ width: "100%", height: "100%" }}
      mapStyle={{
        'version': 8,
        'sources': {
          'raster-tiles': {
            'type': 'raster',
            'tiles': ['https://tile.openstreetmap.org/{z}/{x}/{y}.png'],
            'tileSize': 256,
            'attribution':
              '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          }
        },
        'layers': [
          {
            'id': 'simple-tiles',
            'type': 'raster',
            'source': 'raster-tiles',
            'minzoom': 0,
            'maxzoom': 22
          }
        ]
      }}
    >
      <Marker longitude={point.lng} latitude={point.lat} anchor="bottom">
        <FmdGood/>
      </Marker>
    </Map>
  )
}
