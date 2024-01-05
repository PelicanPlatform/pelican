package main

//go:generate go run ../generate

// This should not be included in any release of pelican

// Include more generator functions here but keep them encapsulated
// in their separate files under `generate` package
func main() {
	GenParamEnum()
	GenParamStruct()
	GenPlaceholderPathForNext()
	GenTokenScope()
}
