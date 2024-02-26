package param

import (
	"reflect"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var (
	viperConfig *Config
	configMutex sync.RWMutex
)

// Unmarshal Viper config into a struct viperConfig and returns it
func UnmarshalConfig() (*Config, error) {
	configMutex.Lock()
	defer configMutex.Unlock()
	viperConfig = new(Config)
	err := viper.Unmarshal(viperConfig)
	if err != nil {
		return nil, err
	}

	return viperConfig, nil
}

// Return the unmarshaled viper config struct as a pointer
func GetUnmarshaledConfig() (*Config, error) {
	configMutex.RLock()
	defer configMutex.RUnlock()
	if viperConfig == nil {
		return nil, errors.New("Config hasn't been unmarshaled yet.")
	}
	return viperConfig, nil
}

// Helper function to set a parameter field entry in configWithType
func setField(fieldType reflect.Type, value interface{}) reflect.Value {
	field := reflect.New(fieldType).Elem()
	sliceInterfaceType := reflect.TypeOf([]interface{}(nil))

	// Check if the type of the value is nil
	if reflect.TypeOf(value) == nil {
		// If the value is nil, it is a object-type config without value
		field.FieldByName("Type").SetString("[]object")
	} else {
		if reflect.TypeOf(value) == sliceInterfaceType {
			field.FieldByName("Type").SetString("[]object")
		} else {
			field.FieldByName("Type").SetString(reflect.TypeOf(value).String())
		}
		field.FieldByName("Value").Set(reflect.ValueOf(value))
	}

	return field
}

// Helper function to convert config struct to configWithType struct using reflection
func convertStruct(srcVal, destVal reflect.Value) {
	// If the source or destination is a pointer, get the underlying element
	if srcVal.Kind() == reflect.Ptr {
		srcVal = srcVal.Elem()
	}
	if destVal.Kind() == reflect.Ptr {
		destVal = destVal.Elem()
	}

	for i := 0; i < srcVal.NumField(); i++ {
		srcField := srcVal.Field(i)
		destField := destVal.FieldByName(srcVal.Type().Field(i).Name)

		// Check if the field is a struct and handle recursively
		if srcField.Kind() == reflect.Struct {
			nestedSrc := srcField
			nestedDest := destField

			// Make sure nestedDest is addressable
			if !nestedDest.CanSet() {
				nestedDest = reflect.New(nestedDest.Type()).Elem()
			}

			convertStruct(nestedSrc, nestedDest)
			destField.Set(nestedDest) // Set the converted struct back
		} else {
			// Handle non-struct fields
			if destField.CanSet() {
				destFieldType := destField.Type()
				convertedField := setField(destFieldType, srcField.Interface())
				destField.Set(convertedField)
			}
		}
	}
}

// Convert a config struct to configWithType struct
func ConvertToConfigWithType(rawConfig *Config) *configWithType {
	typedConfig := configWithType{}

	srcVal := reflect.ValueOf(rawConfig).Elem()
	destVal := reflect.ValueOf(&typedConfig).Elem()
	convertStruct(srcVal, destVal)
	return &typedConfig
}
