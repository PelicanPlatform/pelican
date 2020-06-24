package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
)

// Redirector
var global_redirector string = "http://redirector.osgstorage.org:8000"

func main() {

	// Basic flag declarations are available for string,
	// integer, and boolean options. Here we declare a
	// string flag `word` with a default value `"foo"`
	// and a short description. This `flag.String` function
	// returns a string pointer (not a string value);
	// we'll see how to use this pointer below.
	//wordPtr := flag.String("cache", "", "The cache to use")
	//debug := flag.Bool("debug", false, "Debug output")

	// This declares `numb` and `fork` flags, using a
	// similar approach to the `word` flag.
	//numbPtr := flag.Int("numb", 42, "an int")
	//boolPtr := flag.Bool("fork", false, "a bool")

	// It's also possible to declare an option that uses an
	// existing var declared elsewhere in the program.
	// Note that we need to pass in a pointer to the flag
	// declaration function.
	//var svar string
	//flag.StringVar(&svar, "svar", "bar", "a string var")

	// Once all flags are declared, call `flag.Parse()`
	// to execute the command-line parsing.
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Must have at least 2 arguments\n")
		os.Exit(1)
	}
	source := args[0]
	//dest := args[1]

	// Combine the paths
	u, _ := url.Parse(global_redirector)
	u.Path = path.Join(u.Path, source)

	fmt.Printf("Trying URL: %v\n", u.String())
	redir := GetRedirect(u.String())
	fmt.Printf("ERROR: %v\n", redir)

}
