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

// File propfind_pelican_props.go implements the golang.org/x/net/webdav
// DeadPropsHolder interface for aferoFile so PROPFIND responses can
// surface Pelican-specific properties fed by the object_metadata DAO.
//
// Today the only such property is `source-etag` — set on any object
// produced by a successful third-party copy (COPY / TPC), cleared by
// any direct PUT to the same path. A sync client that has previously
// pulled the object from the same source can compare its own recorded
// ETag against the value here; a match means the local copy is still
// authoritative and the sync can be skipped.
//
// The property is read-only. Attempts to PROPPATCH it get a
// 409 Conflict via a "not authorised" propstat, matching the DAV
// convention for a live (server-computed) property that clients may
// not modify.

package origin_serve

import (
	"encoding/xml"
	"errors"
	"net/http"

	"golang.org/x/net/webdav"
)

// PelicanDAVNamespace is the XML namespace URI for Pelican-specific
// dead properties. Exported so tests and downstream consumers can
// reference the same URI.
const PelicanDAVNamespace = "https://pelicanplatform.org/dav/"

// PropSourceEtag is the local name of the source-etag property.
// Full XML name is {PelicanDAVNamespace}source-etag.
const PropSourceEtag = "source-etag"

// sourceEtagXMLName is the composite name used to key the DeadProps
// map; kept as a var so tests can reuse it.
var sourceEtagXMLName = xml.Name{Space: PelicanDAVNamespace, Local: PropSourceEtag}

// errReadOnlyProperty is returned by Patch when a caller tries to
// modify a Pelican-owned property. webdav renders errors from Patch
// as 409 propstats when they are typed this way.
var errReadOnlyProperty = errors.New("pelican dead property is read-only")

// DeadProps satisfies webdav.DeadPropsHolder. It looks up the object's
// live row via the DAO and, when a source_etag is stored, returns
// {https://pelicanplatform.org/dav/}source-etag. Returns an empty map
// (not nil) so the webdav propfind path treats "we have no dead props"
// the same as "we have some but none of the requested names".
//
// Nil-safe against a missing observation config: aferoFile has no
// obs when TrackAccess is off origin-wide, and the DAO / cache are
// nil in that case. Returns an empty map.
func (af *aferoFile) DeadProps() (map[xml.Name]webdav.Property, error) {
	out := map[xml.Name]webdav.Property{}
	if af == nil || af.obs == nil || af.obs.dao == nil {
		return out, nil
	}
	fedPath := joinFederationPath(af.obs.namespace, af.webdavName)
	row, err := af.obs.dao.LookupLive(af.ctx, af.obs.namespace, fedPath)
	if err != nil || row == nil || row.SourceEtag == nil || *row.SourceEtag == "" {
		return out, nil
	}
	// InnerXML holds the raw XML bytes between <source-etag>...</source-etag>.
	// XML-escape to guard against a source that (validly, per HTTP)
	// returned an ETag containing "<" or "&".
	var buf []byte
	buf = xmlEscapeInto(buf, *row.SourceEtag)
	out[sourceEtagXMLName] = webdav.Property{
		XMLName:  sourceEtagXMLName,
		InnerXML: buf,
	}
	return out, nil
}

// Patch satisfies webdav.DeadPropsHolder. All Pelican-owned property
// names in the write list get a 409 propstat; any other names are
// passed through unchanged so a future dead-props store could layer
// on. Today no such store exists, so unknown names get a 409 too.
func (af *aferoFile) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	failed := webdav.Propstat{Status: http.StatusConflict}
	for _, patch := range patches {
		for _, prop := range patch.Props {
			failed.Props = append(failed.Props, webdav.Property{XMLName: prop.XMLName})
		}
	}
	if len(failed.Props) == 0 {
		return nil, nil
	}
	return []webdav.Propstat{failed}, nil
}

// xmlEscapeInto appends s to buf with XML character escaping for
// element text content. Only "<", ">", and "&" require escaping in
// text; quotes are only meaningful inside attribute values and
// leaving them alone keeps the on-wire property tidy for the common
// case of an ETag like "abc123" (a leading + trailing "). Written
// inline rather than routing through encoding/xml.EscapeText to
// avoid the io.Writer indirection on every PROPFIND row.
func xmlEscapeInto(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '<':
			buf = append(buf, "&lt;"...)
		case '>':
			buf = append(buf, "&gt;"...)
		case '&':
			buf = append(buf, "&amp;"...)
		default:
			buf = append(buf, c)
		}
	}
	return buf
}

// Compile-time assertion that aferoFile satisfies the interface. If a
// caller ever changes the DeadProps or Patch signature, this line
// stops compiling before the webdav handler falls back to the no-dead-
// props path silently.
var _ webdav.DeadPropsHolder = (*aferoFile)(nil)
