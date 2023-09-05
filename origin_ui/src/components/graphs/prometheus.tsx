"use client"

import {ChartData} from "chart.js";

const USEFUL_METRICS = ["xrootd_server_connection_count", "xrootd_monitoring_packets_received"]

export interface DataPoint {
    x: any;
    y: any;
}

export async function query_raw(query: string): Promise<DataPoint[]> {
    let response = await fetch(`/api/v1.0/prometheus/query?query=${query}`)

    if (response.status !== 200) {
        throw new Error(`Prometheus query returned status ${response.status}`)
    }

    let json = await response.json()

    if (json.status !== "success") {
        throw new Error(`Prometheus query returned status ${json.status}`)
    }

    // This will return the list of time and value tuples [1693918800,"0"],[1693919100,"0"]...
    let label_data_tuples = json.data.result[0].values
    let data: DataPoint[] = []
    label_data_tuples.forEach((tuple: any) => {

        // Decompose the epoch time to a Date object
        let d = new Date(0)
        d.setUTCSeconds(tuple[0])

        data.push({x: d.toLocaleTimeString(), y: tuple[1]})
    })

    return data
}

export async function query_basic(metric: string, duration: string, resolution: string): Promise<DataPoint[]> {
    let query = `${metric}[${duration}:${resolution}]`
    return query_raw(query)
}

export async function query_rate(metric: string, rate: string, duration: string, resolution: string): Promise<DataPoint[]>  {
    let query = `rate(${metric}[${rate}])[${duration}:${resolution}]`
    return query_raw(query)
}
