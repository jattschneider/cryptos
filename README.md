# Go Cryptos

Cryptos is a Go library that implements a simple string encrypt/decrypt.

## Getting Started

Just a quick example how to use the cryptos library:

#### main.go
```
package main

import (
	"flag"
	"fmt"

	"github.com/jattschneider/cryptos"
)

func init() {
	flag.Parse()
}

func main() {
	
	// 32 bytes Key
	key, err := cryptos.Base64Decode("lJVRh3lGtxZwlwplx+Wz9XbJSEouhfcPKmYbBM45ODE=")
	if err != nil {
		return
	}
	// 12 bytes Nonce
	nonce, err := cryptos.Base64Decode("hoOLlooQPN21ufCy")
	if err != nil {
		return
	}

	
	msg := "Hello Encrypter!"
	es, err := cryptos.EncryptString(key, nonce, msg)
	if err != nil {
		return
	}
	
	// AES-256
	// "ENC(cLqUafMcfzJOt3FyOLmIAqwVJJAoXj3o3h3cZrM4EIo=)"
	if !IsEncryptedString(es) {
		return
	}

	ds, err := cryptos.DecryptString(key, nonce, es)
	if err != nil {
		return
	}

}
```

```
$ go run main.go
```

### Installing

```
go get -v github.com/jattschneider/cryptos
```

## Built With

* [Go](https://golang.org/) - The Go Programming Language
* [dep](https://golang.github.io/dep/) - Dependency management for Go
* [glog](https://github.com/golang/glog) - Leveled execution logs for Go

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/jattschneider/config/tags). 

## Authors

* **José Augusto Schneider** - *Initial work* - [jattschneider](https://github.com/jattschneider)


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
