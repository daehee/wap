package wap

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

const wapSourceURL = "https://raw.githubusercontent.com/AliasIO/Wappalyzer/master/src/technologies.json"

func DownloadSource(to string) error {
	resp, err := http.Get(wapSourceURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(to)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	return err
}

type temp struct {
	Technologies map[string]*json.RawMessage `json:"technologies"`
	Categories   map[string]*json.RawMessage `json:"categories"`
}

type Fingerprint struct {
	Name       string   `json:"name,omitempty"`
	Categories []string `json:"categories,omitempty"`

	Cats       []int             `json:"cats,omitempty"`
	CertIssuer []string          `json:"certIssuer,omitempty"`
	Cookies    map[string]string `json:"cookies,omitempty"`
	Cpe        string            `json:"cpe,omitempty"`
	Css        []string          `json:"css,omitempty"`
	Excludes   []string          `json:"excludes,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	HTML       []string          `json:"html,omitempty"`
	Icon       string            `json:"icon,omitempty"`
	Implies    []string          `json:"implies,omitempty"`
	Js         map[string]string `json:"js,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
	Robots     []string          `json:"robots,omitempty"`
	Scripts    []string          `json:"scripts,omitempty"`
	URL        string            `json:"url,omitempty"`
	Website    string            `json:"website,omitempty"`
}

type Category struct {
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type Wappalyzer struct {
	Fingerprints []*Fingerprint
	Categories   map[string]*Category
}

// Fingerprints extracts a slice of Fingerprint structs from given source file
func Fingerprints(filename string) (*Wappalyzer, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseWapJSON(b)
}

func parseWapJSON(b []byte) (*Wappalyzer, error) {
	// unmarshal wappalyze fingerprints into temporary buffer
	tmp := &temp{}
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return nil, err
	}

	wap := &Wappalyzer{}
	wap.Fingerprints = make([]*Fingerprint, 0)
	wap.Categories = make(map[string]*Category)
	for k, v := range tmp.Categories {
		catg := &Category{}
		if err = json.Unmarshal(*v, catg); err != nil {
			return nil, err
		}
		wap.Categories[k] = catg
	}
	for k, v := range tmp.Technologies {
		fp := &Fingerprint{}
		fp.Name = k

		var jsonMap map[string]json.RawMessage
		if err := json.Unmarshal(*v, &jsonMap); err != nil {
			return nil, err
		}
		// can't unmarshal fields containing multiple types, such as string or []string
		// convert all values in temporary buffer from interface{} to explicit type for export
		for jk, jv := range jsonMap {
			switch jk {
			case "cats":
				var jz []int
				if err := json.Unmarshal(jv, &jz); err != nil {
					return nil, err
				}
				parseCats(jz, fp, &wap.Categories)
			case "certIssuer":
				fp.CertIssuer = wapStringSlice(jv)
			case "cookies":
				fp.Cookies = wapMap(jv)
			case "cpe":
				fp.Cpe = wapString(jv)
			case "css":
				fp.Css = wapStringSlice(jv)
			case "excludes":
				fp.Excludes = wapStringSlice(jv)
			case "headers":
				fp.Headers = wapMap(jv)
			case "html":
				fp.HTML = wapStringSlice(jv)
			case "icon":
				fp.Icon = wapString(jv)
			case "implies":
				fp.Excludes = wapStringSlice(jv)
			case "js":
				fp.Js = wapMap(jv)
			case "meta":
				fp.Meta = wapMap(jv)
			case "robots":
				fp.Robots = wapStringSlice(jv)
			case "scripts":
				fp.Scripts = wapStringSlice(jv)
			case "url":
				fp.URL = wapString(jv)
			case "website":
				fp.Website = wapString(jv)
			}
		}
		wap.Fingerprints = append(wap.Fingerprints, fp)
	}
	return wap, nil
}

func wapStringSlice(v json.RawMessage) []string {
	var u interface{}
	if err := json.Unmarshal(v, &u); err != nil {
		log.Printf("%v: %+v", err, v)
	}
	var ss []string
	switch s := u.(type) {
	case string:
		ss = append(ss, cleanWapMeta(s))
	case []string:
		for i, v := range s {
			s[i] = cleanWapMeta(v)
		}
		return s
	}
	return ss
}

func wapString(v json.RawMessage) string {
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		log.Printf("%v: %+v", err, v)
	}
	return cleanWapMeta(s)
}

func wapMap(v json.RawMessage) map[string]string {
	var m map[string]string
	if err := json.Unmarshal(v, &m); err != nil {
		log.Printf("%v: %+v", err, v)
	}
	for k, v := range m {
		m[k] = cleanWapMeta(v)
	}
	return m
}

func cleanWapMeta(s string) string {
	split := strings.Split(s, "\\;")
	return split[0]
}

func parseCats(src []int, dst *Fingerprint, categoriesCatalog *map[string]*Category) {
	for _, categoryID := range src {
		dst.Categories = append(dst.Categories, (*categoriesCatalog)[strconv.Itoa(categoryID)].Name)
	}
}

func (w *Wappalyzer) FingerprintByName(s string) (*Fingerprint, error) {
	fps := w.Fingerprints
	sort.Slice(fps, func(i, j int) bool {
		return fps[i].Name <= fps[j].Name
	})
	cand := sort.Search(len(fps), func(i int) bool {
		return fps[i].Name >= s
	})

	if fps[cand].Name == s {
		return fps[cand], nil
	} else {
		return nil, fmt.Errorf("no fingerprint for %s", s)
	}
}
