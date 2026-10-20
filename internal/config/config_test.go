package config

import (
	"testing"
	"time"
)

func TestStrictDurations(t *testing.T) {
	type settings struct {
		Timeout time.Duration `json:"timeout,omitempty"`
		Name    string        `json:"name"`
	}
	var s settings
	if e := Decode([]byte(`{"timeout":"2s","name":"edge"}`), &s); e != nil || s.Timeout != 2*time.Second {
		t.Fatalf("%+v %v", s, e)
	}
	if e := Decode([]byte(`{"timeout":2000000000}`), &s); e != nil || s.Timeout != 2*time.Second {
		t.Fatal(s, e)
	}
	for _, raw := range []string{`null`, `[]`, `{"typo":1}`, `{"timeout":"-1s"}`, `{"timeout":-1}`, `{"timeout":null}`, `{"timeout":"later"}`, `{} {}`} {
		if e := Decode([]byte(raw), &s); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var nilSettings *settings
	if e := Decode([]byte(`{}`), nilSettings); e == nil {
		t.Fatal("nil pointer accepted")
	}
}
