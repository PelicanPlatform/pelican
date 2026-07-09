/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// Command cshared builds the libLotMan shared library: a C-ABI front end over
// the native Go lot engine (lotman/core), re-exposing the historical libLotMan
// interface (see reference/lotman/src/lotman.h) so external C consumers — most
// notably the XRootD pfc purge plugin — keep working without the original C++
// library.
//
// It is NOT imported by pelican-server, which embeds lotman/core directly as
// pure Go. This package is compiled on its own with:
//
//	go build -buildmode=c-shared -o libLotMan.so ./lotman/cshared
//
// The wrapper holds its lot database under the "lot_home" context key (set via
// lotman_set_context_str), opening <lot_home>/lots.sqlite — the same file the
// V1 (XRootD) Pelican cache uses — so the cache and the purge plugin share one
// lot database. The on-disk SQLite schema is the native engine's, which differs
// from the original C++ library's; a C consumer and a Pelican cache must not
// share a lot database created by the old C++ library across the cutover.
package main
