// Package env reads the settings of the examples from the environment.
package env

import (
	"log"
	"os"
)

// Must returns the value of the variable name and stops the program when it is not set.
func Must(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is not set", name)
	}
	return v
}

// Or returns the value of the variable name, or def when it is not set.
func Or(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
