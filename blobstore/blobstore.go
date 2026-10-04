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

// Package blobstore holds the object-storage plumbing shared by the origin's
// blob backend and the cache's tiering targets: opening a bucket, telling a
// missing object from a failure, and keeping credentials out of logs.
//
// Both callers sit on gocloud.dev/blob, and before this package each carried
// its own copy of these pieces.  The copies had already drifted apart in ways
// that mattered -- each redacted secrets the other leaked, and only one
// recognised the bare 404s several S3-compatible services return -- so they
// live here once.
//
// It sits low in the import graph -- it imports only utils, for the URL
// credential rules it shares with code that must not link a cloud SDK -- so
// both the origin and the cache can use it without creating a cycle.
package blobstore

import (
	"context"
	"net/url"
	"sort"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // register azblob:// URL opener
	_ "gocloud.dev/blob/gcsblob"   // register gs:// URL opener
	"gocloud.dev/blob/s3blob"

	"github.com/pelicanplatform/pelican/utils"
)

// S3Options names an S3 or S3-compatible bucket by its explicit fields.
type S3Options struct {
	// ServiceURL is the endpoint (e.g. https://s3.us-east-1.amazonaws.com).
	// Empty means the SDK's default endpoint for Region.
	ServiceURL string
	Region     string
	Bucket     string
	// URLStyle is "path" (the default) or "virtual".  Path style is the
	// default because most S3-compatible services and custom endpoints
	// require it.
	URLStyle string
	// AccessKey and SecretKey are static credentials.  When both are empty
	// the SDK's ambient credential chain is used (environment, shared
	// config, instance role).  Callers that want anonymous access instead
	// -- reasonable for a public, read-only bucket -- should open an
	// s3:// URL with anonymous=true via OpenURL.
	AccessKey string
	SecretKey string
}

// OpenS3 builds an S3 client from opts and opens the bucket over it.  The
// client is returned too, for the few operations with no portable gocloud
// equivalent (multipart-upload housekeeping, for instance).
//
// Credentials are attached to this client only; they are never written into
// the process environment, where they would leak into every other S3 client.
// Opening is lazy: no request reaches the service here.
func OpenS3(ctx context.Context, opts S3Options) (*blob.Bucket, *s3.Client, error) {
	if opts.Bucket == "" {
		return nil, nil, errors.New("an S3 bucket name is required")
	}
	var cfgOpts []func(*awsconfig.LoadOptions) error
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(opts.Region))
	}
	if opts.AccessKey != "" && opts.SecretKey != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to load AWS configuration for bucket %q", opts.Bucket)
	}

	var s3Opts []func(*s3.Options)
	if !strings.EqualFold(opts.URLStyle, "virtual") {
		s3Opts = append(s3Opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	if opts.ServiceURL != "" {
		endpoint := opts.ServiceURL
		s3Opts = append(s3Opts, func(o *s3.Options) { o.BaseEndpoint = &endpoint })
	}
	client := s3.NewFromConfig(awsCfg, s3Opts...)

	// The upload manager does not inherit the checksum-calculation setting
	// from the config, so propagate it; third-party S3 providers reject the
	// SDK's default checksums otherwise.
	bucket, err := s3blob.OpenBucket(ctx, client, opts.Bucket, &s3blob.Options{
		RequestChecksumCalculation: awsCfg.RequestChecksumCalculation,
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to open bucket %q", opts.Bucket)
	}
	return bucket, client, nil
}

// OpenURL opens a bucket named by a gocloud.dev URL ("s3://bucket",
// "gs://bucket", "azblob://container", ...).
//
// gocloud's openers put the whole URL into their error messages -- the S3
// and GCS openers, and the scheme dispatcher when no driver matches -- so a
// secret embedded in the URL would reach whatever logs the error.  The error
// returned here carries a scrubbed message; the original stays reachable
// through errors.Is and errors.As, but is never formatted.
func OpenURL(ctx context.Context, rawURL string) (*blob.Bucket, error) {
	bucket, err := blob.OpenBucket(ctx, rawURL)
	if err != nil {
		return nil, &openError{
			msg:   "failed to open bucket " + utils.RedactURLCredentials(rawURL) + ": " + scrubURL(err.Error(), rawURL),
			cause: err,
		}
	}
	return bucket, nil
}

// openError is an open failure whose message has had the URL scrubbed out.
type openError struct {
	msg   string
	cause error
}

func (e *openError) Error() string { return e.msg }
func (e *openError) Unwrap() error { return e.cause }

// scrubURL removes every sensitive part of rawURL from msg: the URL itself in
// each spelling gocloud might print, and the individual secrets in case one
// is quoted on its own.  The whole-URL forms become the redacted URL; lone
// secrets become "redacted".
func scrubURL(msg, rawURL string) string {
	redacted := utils.RedactURLCredentials(rawURL)
	wholeForms := []string{rawURL}
	var secrets []string
	if u, err := url.Parse(rawURL); err == nil {
		wholeForms = append(wholeForms, u.String())
		if u.User != nil {
			secrets = append(secrets, u.User.Username())
			if pw, ok := u.User.Password(); ok {
				secrets = append(secrets, pw)
			}
		}
		for key, values := range u.Query() {
			if utils.IsSecretURLParam(key) {
				for _, v := range values {
					secrets = append(secrets, v, url.QueryEscape(v))
				}
			}
		}
	}
	for _, form := range wholeForms {
		if form != "" {
			msg = strings.ReplaceAll(msg, form, redacted)
		}
	}
	// Longest first, so a secret that contains another is replaced whole.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "redacted")
		}
	}
	return msg
}
