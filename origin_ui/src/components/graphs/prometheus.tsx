/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

"use client"

import {ChartData} from "chart.js";

import {isLoggedIn} from "@/helpers/login";

const USEFUL_METRICS = ["xrootd_server_connection_count", "xrootd_monitoring_packets_received"]

export interface DataPoint {
    x: any;
    y: any;
}

export async function query_raw(query: string): Promise<DataPoint[]> {

    //Check if the user is logged in
    if(!(await isLoggedIn())){
        window.location.replace("/view/initialization/code/")
    }

    let response = await fetch(`/api/v1.0/prometheus/query?query=${query}`)

    if (response.status !== 200) {
        throw new Error(`Prometheus query returned status ${response.status}`)
    }

    let json = await response.json()

    if (json.status !== "success") {
        throw new Error(`Prometheus query returned status ${json.status}`)
    }


    if(json.data.result.length == 0){
        return []
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
