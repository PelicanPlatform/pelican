package stashcp

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

func version_status(filePath string) (string, error) {
	base := path.Base(filePath)
	dir := path.Dir(filePath)

	hash, err := unique_hash(filePath)
	if err != nil {
		return "", err
	}
	return path.Join(dir, fmt.Sprintf("%s.%s", base, hash)), nil
}

func generate_destination(filePath string, originPrefix string, shadowOriginPrefix string) (string, error) {
	hashRaw, err := version_status(filePath)
	if err != nil {
		return "", err
	}
	hashString := path.Clean(hashRaw)
	cleanedOriginPrefix := path.Clean(originPrefix)
	if strings.HasPrefix(hashString, cleanedOriginPrefix) {
		return shadowOriginPrefix + hashString[len(cleanedOriginPrefix):], nil
	}
	return "", errors.New("File path must have the origin prefix")
}

func DoShadowIngest(sourceFile string, originPrefix string, shadowOriginPrefix string) (int64, string, error) {
	for idx := 0; idx < 10; idx++ {
		shadowFile, err := generate_destination(sourceFile, originPrefix, shadowOriginPrefix)
		if err != nil {
			return 0, "", err
		}
		methods := []string{"http"}

		remoteSize, err := CheckOSDF(shadowFile, methods)
		if err != nil {
			return 0, "", err
		}
		if remoteSize == 0 {
			return 0, shadowFile, err
		}

		uploadBytes, err := DoStashCPSingle(sourceFile, shadowFile, methods, false)

		// See if the file was modified while we were uploading; if not, we'll return success
		shadowFilePost, err := generate_destination(sourceFile, originPrefix, shadowOriginPrefix)
		if err != nil {
			return 0, "", err
		}
		if shadowFilePost == shadowFile {	
			return uploadBytes, shadowFile, err
		}
	}
	return 0, "", errors.New("After 10 upload attempts, file was still being modified during ingest.")
}
