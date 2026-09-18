// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// encoding/json otherwise accepts duplicate and case-insensitive struct keys.
// Check the document before decoding it into the one canonical Go schema.
func strictJSON(data []byte, target any) error {
	if !utf8.Valid(data) {
		return errors.New("config must be valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := jsonValue(d, 0)
	if err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("config must contain one JSON object")
	}
	if err := checkFields(value, reflect.TypeOf(target).Elem(), "config"); err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("config nesting exceeds 32 levels")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("null is not a configuration value; omit optional fields")
	}
	if token == json.Delim('{') {
		object := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("expected an object key")
			}
			if _, exists := object[name]; exists {
				return nil, fmt.Errorf("duplicate config key %q", name)
			}
			object[name], err = jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
		}
		_, err = d.Token()
		return object, err
	}
	if token == json.Delim('[') {
		array := []any{}
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err = d.Token()
		return array, err
	}
	return token, nil
}

func checkFields(value any, typ reflect.Type, location string) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", location)
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		for name, v := range object {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown field %s.%s (names are case-sensitive)", location, name)
			}
			if err := checkFields(v, field, location+"."+name); err != nil {
				return err
			}
		}
		if typ == reflect.TypeFor[Token]() {
			if reference, exists := object["response_ref"]; exists {
				if reference == "" {
					return fmt.Errorf("%s: response_ref cannot be empty", location)
				}
				if _, exists := object["response"]; exists {
					return fmt.Errorf("%s: use response or response_ref, not both", location)
				}
			}
		}
		if typ == reflect.TypeFor[Response]() {
			if file, exists := object["body_file"]; exists && file == "" {
				return fmt.Errorf("%s: body_file cannot be empty", location)
			}
			bodies := 0
			for _, name := range []string{"body", "body_base64", "body_file"} {
				if _, exists := object[name]; exists {
					bodies++
				}
			}
			if bodies > 1 {
				return fmt.Errorf("%s: use only one of body, body_base64 or body_file", location)
			}
		}
	case reflect.Map:
		if object, ok := value.(map[string]any); ok {
			for name, v := range object {
				if err := checkFields(v, typ.Elem(), location+"."+name); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if array, ok := value.([]any); ok {
			for i, v := range array {
				if err := checkFields(v, typ.Elem(), fmt.Sprintf("%s[%d]", location, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
