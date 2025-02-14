# End to End Fed Tests Package

This package is meant to be a repository of federation tests that test specific Pelican components
when their interaction with other services is important. It has been created as its own package to
avoid the potential for circular dependencies, and as such no functions here should ever be exported.

For example, the Director's health test utility API needs to function with both caches and origins.
Testing these components together is most easily done by using `fed_test_utils` to spin up a new
federation test. However, that package cannot be imported by Director, Cache, or Origin tests directly
because the fed test itself _must_ import those packages, leading to a cyclical dependency.

The `github_scripts` directory contains a similar set of CI tests, but it's easier to write rigorous
tests in go than it is to write them in bash.
