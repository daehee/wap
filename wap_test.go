package wap

import (
    "flag"
    "strings"
    "testing"
)

var testFile = flag.String("test-file", "", "")

const tencentWebsite = "https://007.qq.com/"

func TestParseFile(t *testing.T) {
    w, err := Fingerprints(*testFile)
    if err != nil {
        t.Fatal(err)
    }

    tech, err := w.FingerprintByName("Tencent Waterproof Wall")
    if err != nil {
        t.Fatal(err)
    }
    got := tech.Website
    if strings.Compare(got, tencentWebsite) != 0 {
       t.Errorf("got %v; want %v", got, tencentWebsite)
    }
}
