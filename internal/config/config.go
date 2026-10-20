// Package config reads strict JSON configuration with human-readable Go
// duration values. Numeric durations remain nanoseconds for compatibility.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
)

func Read(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Decode(b, dst)
}

func Decode(b []byte, dst any) error {
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct || reflect.ValueOf(dst).IsNil() {
		return fmt.Errorf("config target must be a struct pointer")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	if fields == nil {
		return fmt.Errorf("config must be a JSON object")
	}
	for i := 0; i < t.Elem().NumField(); i++ {
		f := t.Elem().Field(i)
		if f.Type != reflect.TypeOf(time.Duration(0)) {
			continue
		}
		key := strings.Split(f.Tag.Get("json"), ",")[0]
		if key == "" {
			key = f.Name
		}
		raw, ok := fields[key]
		if !ok || len(raw) == 0 {
			continue
		}
		if raw[0] != '"' {
			var value int64
			if err := json.Unmarshal(raw, &value); err != nil || value < 0 || string(raw) == "null" {
				return fmt.Errorf("%s must be a nonnegative duration", key)
			}
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if d < 0 {
			return fmt.Errorf("%s must not be negative", key)
		}
		fields[key], _ = json.Marshal(int64(d))
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(dst); err != nil {
		return err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON object")
	}
	return nil
}
