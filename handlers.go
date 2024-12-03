package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grafana/dskit/kv/memberlist"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/ring"
)

//go:embed templates/index.gohtml
var indexPageHTML string

func newIndexPageContent() *IndexPageContent {
	return &IndexPageContent{}
}

type indexPageContents struct {
	LinkGroups []IndexPageLinkGroup
}

// IndexPageContent is a map of sections to path -> description.
type IndexPageContent struct {
	mu sync.Mutex

	elements []IndexPageLinkGroup
}

type IndexPageLinkGroup struct {
	weight int
	Desc   string
	Links  []IndexPageLink
}

type IndexPageLink struct {
	Desc string
	Path string
}

// List of weights to order link groups in the same order as weights are ordered here.
const (
	certificateWeight = iota
	metricsWeight
	hostWeight
	hostFactWeight
	defaultWeight
	ringWeight
	memberlistWeight
)

func (pc *IndexPageContent) AddLinks(weight int, groupDesc string, links []IndexPageLink) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.elements = append(pc.elements, IndexPageLinkGroup{weight: weight, Desc: groupDesc, Links: links})
}

func (pc *IndexPageContent) GetContent() []IndexPageLinkGroup {
	pc.mu.Lock()
	els := append([]IndexPageLinkGroup(nil), pc.elements...)
	pc.mu.Unlock()

	sort.Slice(els, func(i, j int) bool {
		if els[i].weight != els[j].weight {
			return els[i].weight < els[j].weight
		}
		return els[i].Desc < els[j].Desc
	})

	return els
}

//go:embed static
var staticFiles embed.FS

func indexHandler(httpPathPrefix string, content *IndexPageContent) http.HandlerFunc {
	templ := template.New("main")
	templ.Funcs(map[string]interface{}{
		"AddPathPrefix": func(link string) string {
			return path.Join(httpPathPrefix, link)
		},
	})
	template.Must(templ.Parse(indexPageHTML))

	return func(w http.ResponseWriter, _ *http.Request) {
		err := templ.Execute(w, indexPageContents{LinkGroups: content.GetContent()})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

//go:embed templates/memberlist_status.gohtml
var memberlistStatusPageHTML string

func memberlistStatusHandler(httpPathPrefix string, kvs *memberlist.KVInitService) http.Handler {
	templ := template.New("memberlist_status")
	templ.Funcs(map[string]interface{}{
		"AddPathPrefix": func(link string) string { return path.Join(httpPathPrefix, link) },
		"StringsJoin":   strings.Join,
	})
	template.Must(templ.Parse(memberlistStatusPageHTML))
	return memberlist.NewHTTPStatusHandler(kvs, templ)
}

func leaderHandler(w http.ResponseWriter, _ *http.Request) {
	name, _ := ring.GetLeader(certstore.AmStore.RingConfig)
	_, _ = io.WriteString(w, fmt.Sprintf("{\"name\":\"%s\"}", name))
}

//go:embed templates/certificate.gohtml
var certificatePageHTML string

type certificateHandlerData struct {
	Now          time.Time
	DefaultDays  int
	Certificates []cert.Certificate
}

func certificateHandler(w http.ResponseWriter, r *http.Request) {
	data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	v := &certificateHandlerData{
		Now:          time.Now(),
		Certificates: data,
		DefaultDays:  config.GlobalConfig.Common.CertDays,
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(v.Certificates); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	templ := template.New("main")
	templ.Funcs(map[string]interface{}{
		"AddPathPrefix": func(link string) string {
			return path.Join("", link)
		},
		"Split": func(s string, d string) []string {
			return strings.Split(s, d)
		},
	})
	template.Must(templ.Parse(certificatePageHTML))

	err = templ.Execute(w, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func httpChallengeHandler(w http.ResponseWriter, r *http.Request) {
	data, err := certstore.AmStore.GetKVRingTokenChallenge(certstore.AmRingChallengeKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if val, ok := data[r.RequestURI]; ok {
		_, _ = io.WriteString(w, val)
	} else {
		http.Error(w, fmt.Sprintf("key %s not found", r.RequestURI), http.StatusNotFound)
	}
}
