package main

import (
	"fmt"

	curl "github.com/andelf/go-curl"
)

// GetRedirect - Get the redirection for a URL
func GetRedirect(url string) string {

	easy := curl.EasyInit()
	defer easy.Cleanup()

	easy.Setopt(curl.OPT_URL, url)
	// make a callback function
	fooTest := func(buf []byte, userdata interface{}) bool {
		println("DEBUG: size=>", len(buf))
		println("DEBUG: content=>", string(buf))
		return true
	}

	easy.Setopt(curl.OPT_WRITEFUNCTION, fooTest)

	if err := easy.Perform(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
	//var redirectURL, err string
	redirectURL, err := easy.Getinfo(curl.INFO_REDIRECT_URL)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
	var strRedirectURL = redirectURL.(string)

	return strRedirectURL

}
