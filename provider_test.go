package sweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libdns/libdns"
)

func TestAppendAndDelete(t *testing.T) {
	var calls []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		switch {
		case req.Method == "getToken":
			w.Write([]byte(`{"jsonrpc":"2.0","result":"tok"}`))
		case r.Header.Get("Authorization") != "Bearer tok":
			w.Write([]byte(`{"error":{"code":-32500,"message":"auth"}}`))
		case req.Method == "info":
			w.Write([]byte(`{"result":{"ips":[[{"type":"A","name":"x","value":"1.1.1.1","index":1},{"type":"TXT","domain":"_acme-challenge","value":"abc","index":3,"category":"mainTxt"}]],"vps":[]}}`))
		default:
			calls = append(calls, req.Params)
			w.Write([]byte(`{"result":true}`))
		}
	}))
	defer srv.Close()

	p := &Provider{Login: "l", Password: "p", BaseURL: srv.URL}
	ctx := context.Background()
	rec := libdns.TXT{Name: "_acme-challenge", Text: "abc"}
	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if calls[0]["subDomain"] != "_acme-challenge" || calls[0]["action"] != "add" {
		t.Fatalf("bad add: %v", calls[0])
	}
	got, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{rec})
	if err != nil || len(got) != 1 {
		t.Fatalf("delete: %v %v", got, err)
	}
	if calls[1]["action"] != "del" || calls[1]["index"] != float64(3) {
		t.Fatalf("bad del: %v", calls[1])
	}
}
