'use client';

import { Chart } from 'react-chartjs-2';
import {
  CategoryScale,
  Chart as ChartJS,
  ChartDataset,
  Colors,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  TimeScale,
  Title,
  Tooltip,
} from 'chart.js';
import { useEffect, useState } from 'react';
import {
  BoxAndWiskers,
  BoxPlotController,
} from '@sgratzl/chartjs-chart-boxplot';

ChartJS.register(
  BoxPlotController,
  BoxAndWiskers,
  TimeScale,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Colors,
  Filler
);

function randomValues(count: number, min: number, max: number) {
  const delta = max - min;
  return Array.from({ length: count }).map(() => Math.random() * delta + min);
}

const boxplotData = {
  // define label tree
  labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
  datasets: [
    {
      label: 'Dataset 1',
      backgroundColor: 'rgba(255,0,0,0.5)',
      borderColor: 'red',
      borderWidth: 1,
      outlierColor: '#999999',
      padding: 10,
      itemRadius: 0,
      data: [
        randomValues(100, 0, 100),
        randomValues(100, 0, 20),
        randomValues(100, 20, 70),
        randomValues(100, 60, 100),
        randomValues(40, 50, 100),
        randomValues(100, 60, 120),
        randomValues(100, 80, 100),
      ],
    },
    {
      label: 'Dataset 2',
      backgroundColor: 'rgba(0,0,255,0.5)',
      borderColor: 'blue',
      borderWidth: 1,
      outlierColor: '#999999',
      padding: 10,
      itemRadius: 0,
      data: [
        randomValues(100, 60, 100),
        randomValues(100, 0, 100),
        randomValues(100, 0, 20),
        randomValues(100, 20, 70),
        randomValues(40, 60, 120),
        randomValues(100, 20, 100),
        randomValues(100, 80, 100),
      ],
    },
  ],
};

export const BytesTransferred = () => {
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    setLoading(false);
  });

  // const chartData = {
  //   labels: data.labels,
  //   datasets: [
  //     {
  //       label: 'Bytes Transferred',
  //       data: data.datasets,
  //       backgroundColor: 'rgba(54, 162, 235, 0.2)',
  //       borderColor: 'rgba(54, 162, 235, 1)',
  //       borderWidth: 1,
  //     },
  //   ],
  // };

  return (
    <Chart
      type='boxplot'
      data={boxplotData}
      options={{
        scales: {
          y: {
            title: {
              display: true,
              text: 'Bytes Transferred',
            },
          },
        },
      }}
    />
  );
};
