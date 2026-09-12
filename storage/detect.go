package storage

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Driver names
const (
	DriverGorm = "gorm"
	DriverEnt  = "ent"
)

// DetectDriver inspects an opaque DB handle and returns the driver name.
//
// Supported inputs:
//   - *gorm.DB
//   - *ent.Client (from github.com/mwangaben/auth/storage/entstore/ent)
//   - any value exposing DB()    *gorm.DB
//   - any value exposing Client() *ent.Client
func DetectDriver(db interface{}) (string, error) {
	if db == nil {
		return "", errors.New("storage: nil db")
	}

	t := reflect.TypeOf(db)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	pkgPath := t.PkgPath()
	typeName := t.Name()

	switch {
	// *gorm.DB  →  pkgPath == "gorm.io/gorm", typeName == "DB"
	case pkgPath == "gorm.io/gorm" && typeName == "DB":
		return DriverGorm, nil

	// *ent.Client — package path ends with "/ent" (generated code)
	// and type name is "Client". This matches
	// "github.com/mwangaben/auth/storage/entstore/ent".
	case typeName == "Client" && strings.HasSuffix(pkgPath, "/ent"):
		return DriverEnt, nil

	// Wrappers exposing DB() / Client()
	case hasMethod(db, "Client"):
		return DriverEnt, nil
	case hasMethod(db, "DB"):
		return DriverGorm, nil
	}

	return "", fmt.Errorf("storage: unsupported db type %s.%s", pkgPath, typeName)
}

func hasMethod(v interface{}, name string) bool {
	_, ok := reflect.TypeOf(v).MethodByName(name)
	return ok
}
