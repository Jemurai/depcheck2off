# Dependency Check to OFF Converter

Convert a dependency check file to OFF format. (see [github.com/owasp/off](https://github.com/owasp/off))

## Running

1. Get a dependency check report in json
1. `go get github.com/jemurai/depcheck2off`
1. `depcheck2off depcheck-report.json`

## Releasing

Depcheck2off works to follow golang best practices.  Therefore, when updating, we need to do the following:

- `go get -u` 
- `go mod tidy`
- `git commit -m "change with version"`
- `git tag v1.0.6`
- `git push origin v1.0.6`

Run the build.sh and get the different types of artifacts and include them in the release.
