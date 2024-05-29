/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
import {useEffect, useState} from "react"
import { Box, LinearProgress, Typography} from "@mui/material";
import {Error, CheckCircle} from "@mui/icons-material";
import { useRouter } from 'next/navigation'
import {User} from "@/index";
import AuthenticatedContent from "@/components/layout/AuthenticatedContent";
import { getErrorMessage } from "@/helpers/util";
import { set } from "lodash";

interface callbackResponse {
  nextUrl: string;
}

export default function Home() {

  const [error, setError] = useState<undefined | string>(undefined)
  const [nextUrl, setNextUrl] = useState<string | undefined>(undefined)
  const [loading, setLoading] = useState(true)
  const [secondsLeft, setSecondsLeft] = useState(5)

  const router = useRouter()

  const postCallback = async (search: string) : Promise<callbackResponse> => {
    const url = new URL("/api/v1.0/origin_ui/globus/auth/callback"+search, window.location.origin)

    const response = await fetch(url, {
      credentials: "include"
    })

    if (response.ok) {
      const resData = await response.json()
      return resData
    } else {
      const errMsg = await getErrorMessage(response)
      return Promise.reject(errMsg)
    }
  }

  useEffect(() => {
    const cbQuery = window.location.search
    const cbQueryParsed = new URLSearchParams(cbQuery)
    if (!cbQueryParsed.get("code") || !cbQueryParsed.get("state")) {
      setError("Invalid request. Query parameter code and state are required")
      setLoading(false)
      return
    }

    let timeout: NodeJS.Timeout | undefined = undefined
    let timer: NodeJS.Timer | undefined = undefined

    postCallback(cbQuery)
    .then((res) => {
      setNextUrl(res.nextUrl)
      timeout = setTimeout(() => {
        router.replace(nextUrl || "/origin/globus")
      }, 5000)

      timer = setInterval(() => {
        setSecondsLeft((was) => ((was - 1) || 0))
      }, 1000)
    })
    .catch((error) => {
      setError("Error contacting server: "+error)}
    ).finally(() => {
      setLoading(false)
    })
    return () => {
      timeout && clearTimeout(timeout)
      timer && clearInterval(timer)
    }
  }, [])


  return (
      <AuthenticatedContent boxProps={{width: "100%"}} redirect={true} checkAuthentication={(u: User) => u?.role == "admin"}>
          <Box pt={10} width={"100%"} height={"100%"} display={"flex"} flexDirection={"column"} alignItems={"center"}>
              <Box width={"100%"} textAlign={"center"}>
                <Typography variant="h4" mb={2}>Setting up Globus Export...</Typography>
                {loading ?
                  <LinearProgress color={error ? "error" : nextUrl !== undefined ? "success" : "info"} /> :
                  <LinearProgress color={error ? "error" : nextUrl !== undefined ? "success" : "info"} variant="determinate" value={100}/>
                }
              </Box>
              <Box sx={{maxWidth: 1000}} mt={4} textAlign={"center"}>
                {error &&
                  <>
                  <Error color="error" sx={{ fontSize: 80 }}/>
                  <Typography mt={2}>{error}</Typography>
                  </>
                }
                {
                  // This is equivalent of a successful response
                  nextUrl !== undefined &&
                  <>
                    <CheckCircle color="success" sx={{ fontSize: 80 }}/>
                    <Typography mt={2}>Globus collection is activated. Server is restarting in {secondsLeft} second...</Typography>
                    <Typography mt={2} variant="body2">You will be redirect to the Globus configuration page shortly.</Typography>
                  </>
                }
              </Box>
          </Box>
      </AuthenticatedContent>
  )
}
