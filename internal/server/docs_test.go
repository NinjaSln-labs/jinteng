package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocsPage(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "http://192.168.1.10:8787/", nil)
	rr := httptest.NewRecorder()
	s.handleDocs(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "http://192.168.1.10:8787") {
		t.Fatal("missing base url")
	}
	if strings.Contains(body, "jt_") {
		t.Fatal("docs page must not embed API tokens")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type %q", ct)
	}
}
