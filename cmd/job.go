/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package main

import (
	"github.com/spf13/cobra"
)

var (
	jobCmd = &cobra.Command{
		Use:   "job",
		Short: "Manage asynchronous transfer jobs",
		Long: `Manage asynchronous transfer jobs created with the --async flag.
Jobs can contain one or more file transfers and can be monitored, listed, and cancelled.`,
	}
)

func init() {
	rootCmd.AddCommand(jobCmd)
}
