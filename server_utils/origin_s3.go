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

package server_utils

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Inherit from the base origin
type S3Origin struct {
	BaseOrigin
}

func (o *S3Origin) Type(_ Origin) server_structs.OriginStorageType {
	return server_structs.OriginStorageS3
}

func (o *S3Origin) handleVolumeMountsExtra() error {
	bucket := param.Origin_S3Bucket.GetString()
	akf := param.Origin_S3AccessKeyfile.GetString()
	skf := param.Origin_S3SecretKeyfile.GetString()

	for i := range o.Exports {
		o.Exports[i].S3Bucket = bucket
		o.Exports[i].S3AccessKeyfile = akf
		o.Exports[i].S3SecretKeyfile = skf
	}

	return nil
}

func (o *S3Origin) handleTopLevelExtra() error {
	if o.Exports == nil {
		return errors.New("internal error -- discovered nil origin exports while processing top-level Origin.XXX configuration")
	} else if len(o.Exports) > 1 {
		return errors.New("internal error -- discovered multiple origin exports while processing top-level Origin.XXX configuration")
	}

	bucket := param.Origin_S3Bucket.GetString()
	akf := param.Origin_S3AccessKeyfile.GetString()
	skf := param.Origin_S3SecretKeyfile.GetString()
	o.Exports[0].S3Bucket = bucket
	o.Exports[0].S3AccessKeyfile = akf
	o.Exports[0].S3SecretKeyfile = skf

	return nil
}

func (o *S3Origin) validateExtra(e *OriginExport, _ /* no S3 len constraints */ int) (err error) {
	s3ServiceUrl := param.Origin_S3ServiceUrl.GetString()
	if s3ServiceUrl == "" {
		return errors.New("Origin.S3ServiceUrl is required for S3 origins")
	}
	if _, err = url.Parse(s3ServiceUrl); err != nil {
		return errors.Wrapf(err, "unable to parse Origin.S3ServiceUrl '%s'", s3ServiceUrl)
	}

	if e.S3Bucket != "" {
		if err = validateBucketName(e.S3Bucket); err != nil {
			return
		}
	}

	akf := e.S3AccessKeyfile
	skf := e.S3SecretKeyfile
	// XOR the akf and skf -- if one is defined, both must be
	if (akf != "" && skf == "") || (akf == "" && skf != "") {
		return errors.New("either both S3AccessKeyfile and S3SecretKeyfile must be set, or neither")
	}

	// Previous XOR guarantees that if akf != "", then skf != "", so we only need to check one
	// to validate both
	if akf != "" {
		if err = validateFile(filepath.Clean(akf)); err != nil {
			return errors.Wrapf(err, "unable to verify S3 access key file %s", akf)
		}
		if err = validateFile(filepath.Clean(skf)); err != nil {
			return errors.Wrapf(err, "unable to verify S3 secret key file %s", skf)
		}
	}

	return nil
}

// Based on the list of "characters to avoid" from
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
func (o *S3Origin) validateStoragePrefix(prefix string) (err error) {
	illegalChars := []string{`\`, "{", "^", "}", "[", "%", "`", "]", "~", "|", "<", ">", `"`, "#"}
	for _, char := range illegalChars {
		if strings.Contains(prefix, char) {
			return errors.Wrapf(ErrInvalidOriginConfig, "Storage prefix %s contains illegal character %s", prefix, char)
		}
	}

	return nil
}

func (o *S3Origin) mapSingleExtra() {
	if len(o.Exports) != 1 {
		return
	}

	e := o.Exports[0]
	if e.S3Bucket != "" {
		viper.Set(param.Origin_S3Bucket.GetName(), e.S3Bucket)
	}
	if e.S3AccessKeyfile != "" {
		viper.Set(param.Origin_S3AccessKeyfile.GetName(), e.S3AccessKeyfile)
	}
	if e.S3SecretKeyfile != "" {
		viper.Set(param.Origin_S3SecretKeyfile.GetName(), e.S3SecretKeyfile)
	}
}

// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func validateBucketName(bucket string) error {
	if len(bucket) == 0 { // We treat 0-length bucket names as a special case
		return nil
	} else {
		// However, if there _is_ a bucket name, it must be between 3 and 63 characters
		if len(bucket) < 3 || len(bucket) > 63 {
			return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s is not between 3 and 63 characters", bucket)
		}
	}

	// Buckets cannot contain ..
	if strings.Contains(bucket, "..") {
		return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s contains invalid '..'", bucket)
	}

	// Buckets must only contain letters, numbers, '.' and '-'
	for _, char := range bucket {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-') {
			return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s contains invalid character %c", bucket, char)
		}
	}

	// Buckets cannot have capital letters
	if strings.ToLower(bucket) != bucket {
		return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s contains capital letters", bucket)
	}

	// Buckets must begin with letter or number and end with letter or number
	if !((bucket[0] >= 'a' && bucket[0] <= 'z') || (bucket[0] >= '0' && bucket[0] <= '9')) ||
		!((bucket[len(bucket)-1] >= 'a' && bucket[len(bucket)-1] <= 'z') || (bucket[len(bucket)-1] >= '0' && bucket[len(bucket)-1] <= '9')) {
		return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s must begin and end with a letter or number", bucket)
	}

	// Buckets cannot begin with sthree- or sthree-configurator or xn--
	if strings.HasPrefix(bucket, "sthree-") || strings.HasPrefix(bucket, "xn--") {
		return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s cannot begin with 'sthree-' or 'sthree-configurator'", bucket)
	}

	// Bucket names cannot end in -s3alias or --ol-s3
	if strings.HasSuffix(bucket, "-s3alias") || strings.HasSuffix(bucket, "--ol-s3") {
		return errors.Wrapf(ErrInvalidOriginConfig, "bucket name %s cannot end with '-s3alias' or '--ol-s3'", bucket)
	}

	return nil
}
