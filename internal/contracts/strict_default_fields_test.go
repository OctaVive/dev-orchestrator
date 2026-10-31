package contracts

import (
	"strings"
	"testing"
)

func TestStrictDefaultJSONFieldNames(t *testing.T) {
	type value struct {
		Name    string
		Count   int
		Ignored string `json:"-"`
	}
	v, err := DecodeConfiguration[value](strings.NewReader(`{"Name":"fixture","Count":1}`))
	if err != nil || v.Name != "fixture" || v.Count != 1 {
		t.Fatal("default JSON names", err)
	}
	for _, raw := range []string{`{"name":"alias"}`, `{"NAME":"alias"}`, `{"Ignored":"hidden"}`, `{"Name":"a","Name":"b"}`, `{"Name":"x","Unknown":1}`} {
		if _, err := DecodeConfiguration[value](strings.NewReader(raw)); err == nil {
			t.Fatal("nonexact field accepted", raw)
		}
	}
}
