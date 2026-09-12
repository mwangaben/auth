//go:build ignore

package main

import (
	"log"
	"path/filepath"
	"runtime"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("failed to determine generate.go location")
	}
	baseDir := filepath.Dir(filename)

	schemaDir := filepath.Join(baseDir, "schema")
	targetDir := filepath.Join(baseDir, "ent")

	if err := entc.Generate(schemaDir, &gen.Config{
		Target:  targetDir,
		Package: "github.com/mwangaben/auth/storage/entstore/ent",
	}); err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}

	log.Println("ent codegen complete →", targetDir)
}
