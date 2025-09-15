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

	"github.com/go-kit/log/level"
	"github.com/grafana/dskit/kv/memberlist"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/models"
	"github.com/fgouteroux/acme_manager/ring"
)

//go:embed templates/index.gohtml
var indexPageHTML string

func newIndexPageContent() *IndexPageContent {
	return &IndexPageContent{}
}

type indexPageContents struct {
	LinkGroups    []IndexPageLinkGroup
	CurrentLeader string
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
	tokenWeight
	metricsWeight
	hostWeight
	hostFactWeight
	defaultWeight
	memberlistWeight
	ringWeight
	swaggerWeight
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
		leader, err := ring.GetLeader(certstore.AmStore.RingConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		err = templ.Execute(w, indexPageContents{LinkGroups: content.GetContent(), CurrentLeader: leader})
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
	name, err := ring.GetLeader(certstore.AmStore.RingConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	_, _ = io.WriteString(w, fmt.Sprintf("{\"name\":\"%s\"}", name))
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "Server is healthy")
}

//go:embed templates/certificate.gohtml
var certificatePageHTML string

type certificateHandlerData struct {
	Now          time.Time
	Certificates []*models.Certificate
}

func certificateListHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := certstore.AmStore.ListAllCertificates()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		var certSlice []*models.Certificate
		for _, cert := range data {
			certSlice = append(certSlice, cert)
		}

		v := &certificateHandlerData{
			Now:          time.Now(),
			Certificates: certSlice,
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
	})
}

func httpChallengeHandler(w http.ResponseWriter, r *http.Request) {
	challengeID := strings.Split(ChallengePath, r.RequestURI)[1]
	challenge, err := certstore.AmStore.GetChallenge(challengeID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_ = level.Error(logger).Log("err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, challenge)
}

//go:embed templates/token.gohtml
var tokenPageHTML string

type tokenHandlerData struct {
	Now    time.Time
	Tokens map[string]*models.Token
}

func tokenListHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := certstore.AmStore.ListAllTokens()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		tokenData := make(map[string]*models.Token)
		for k, v := range data {
			tokenData[strings.TrimPrefix(k, certstore.TokenPrefix+"/")] = v
		}

		v := &tokenHandlerData{
			Now:    time.Now(),
			Tokens: tokenData,
		}

		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(v.Tokens); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		templ := template.New("main")
		templ.Funcs(map[string]interface{}{
			"AddPathPrefix": func(link string) string {
				return path.Join("", link)
			},
			"Join": func(s []string, d string) string {
				return strings.Join(s, d)
			},
		})
		template.Must(templ.Parse(tokenPageHTML))

		err = templ.Execute(w, v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func LoggerHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Start timer
		start := time.Now()

		lrw := NewLoggingResponseWriter(w)

		next.ServeHTTP(lrw, req)

		// Stop timer
		stop := time.Now()

		_ = level.Info(logger).Log(
			"method", req.Method,
			"path", req.URL.Path,
			"status_code", lrw.statusCode,
			"user", w.Header().Get("user"),
			"duration", stop.Sub(start).Milliseconds(),
			"client_ip", GetClientIP(req),
			"length", lrw.length,
		)
	})
}

func GetClientIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = strings.Split(r.RemoteAddr, ":")[0]
	}
	return IPAddress
}

type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	length     int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *LoggingResponseWriter {
	// WriteHeader(int) is not called if our response implicitly returns 200 OK, so
	// we default to that status code.
	return &LoggingResponseWriter{w, http.StatusOK, 0}
}

func (lrw *LoggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *LoggingResponseWriter) Write(b []byte) (n int, err error) {
	n, err = lrw.ResponseWriter.Write(b)
	lrw.length += n
	return
}

func (lrw *LoggingResponseWriter) Length() int {
	return lrw.length
}
