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

// Package lotjson holds the JSON wire schema for lots (the historical lotman
// document shape, sizes expressed in GB) and the conversions between it and the
// byte-based lotman/core model.
//
// It depends only on lotman/core and the standard library — never on any
// pelican package — so it can be shared by both the Pelican-coupled lotman
// adapter and the standalone C-ABI shared library (lotman/cshared) without
// dragging Pelican's configuration and server dependencies into the latter.
package lotjson
