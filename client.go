package sweb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://api.sweb.ru"
	authEndpoint   = "/notAuthorized/"
	dnsEndpoint    = "/domains/dns"
)

// rpcError is a JSON-RPC error returned by the sweb.ru API.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("sweb api error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      string         `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// txtRecord is a TXT record as reported by the "info" method.
type txtRecord struct {
	Index int
	Name  string
	Value string
}

type client struct {
	baseURL  string
	login    string
	password string
	http     *http.Client

	mu    sync.Mutex
	token string
	seq   int
}

func (c *client) base() string {
	if c.baseURL != "" {
		return strings.TrimRight(c.baseURL, "/")
	}
	return defaultBaseURL
}

func (c *client) httpClient() *http.Client {
	if c.http != nil {
		return c.http
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *client) nextID() string {
	c.seq++
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(c.seq)
}

// do performs a single JSON-RPC call.
func (c *client) do(ctx context.Context, endpoint, method string, params map[string]any, token string) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: c.nextID()})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out rpcResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("sweb api: unexpected response (HTTP %d): %w", resp.StatusCode, err)
	}
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func (c *client) fetchToken(ctx context.Context) (string, error) {
	if c.login == "" || c.password == "" {
		return "", fmt.Errorf("sweb: login and password (or token) must be configured")
	}
	res, err := c.do(ctx, authEndpoint, "getToken", map[string]any{"login": c.login, "password": c.password}, "")
	if err != nil {
		return "", fmt.Errorf("getting token: %w", err)
	}
	var tok string
	if err := json.Unmarshal(res, &tok); err != nil || tok == "" {
		return "", fmt.Errorf("sweb: unexpected getToken result: %s", string(res))
	}
	return tok, nil
}

// call performs an authorized call, obtaining a token when needed and
// retrying once with a fresh token if a cached one was rejected.
func (c *client) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cached := c.token != ""
	if !cached {
		tok, err := c.fetchToken(ctx)
		if err != nil {
			return nil, err
		}
		c.token = tok
	}
	res, err := c.do(ctx, dnsEndpoint, method, params, c.token)
	if err != nil && cached && c.login != "" && c.password != "" {
		if _, isRPC := err.(*rpcError); isRPC {
			tok, terr := c.fetchToken(ctx)
			if terr != nil {
				return nil, terr
			}
			c.token = tok
			return c.do(ctx, dnsEndpoint, method, params, c.token)
		}
	}
	return res, err
}

// listTXT returns all TXT records of the domain.
func (c *client) listTXT(ctx context.Context, domain string) ([]txtRecord, error) {
	res, err := c.call(ctx, "info", map[string]any{"domain": domain})
	if err != nil {
		return nil, err
	}
	items, err := flattenRecords(res)
	if err != nil {
		return nil, err
	}
	var out []txtRecord
	for _, it := range items {
		if !strings.EqualFold(rawString(it["type"]), "TXT") {
			continue
		}
		name := rawString(it["name"])
		if name == "" {
			name = rawString(it["domain"])
		}
		idx, _ := strconv.Atoi(rawString(it["index"]))
		out = append(out, txtRecord{Index: idx, Name: name, Value: rawString(it["value"])})
	}
	return out, nil
}

func (c *client) addTXT(ctx context.Context, domain, sub, value string) error {
	res, err := c.call(ctx, "editTxt", map[string]any{
		"domain": domain, "action": "add", "subDomain": sub, "value": value,
	})
	if err != nil {
		return err
	}
	return checkOK(res)
}

func (c *client) deleteTXT(ctx context.Context, domain string, index int) error {
	res, err := c.call(ctx, "editTxt", map[string]any{
		"domain": domain, "action": "del", "index": index,
	})
	if err != nil {
		return err
	}
	return checkOK(res)
}

func checkOK(res json.RawMessage) error {
	switch strings.TrimSpace(string(res)) {
	case "true", "1", `"1"`:
		return nil
	}
	return fmt.Errorf("sweb: operation failed, API returned %s", string(res))
}

// rawString decodes a JSON string or number into a string.
func rawString(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(r, &n) == nil {
		return n.String()
	}
	return ""
}

// flattenRecords extracts record objects from an "info" result. Per the API
// docs the result is {"ips": [[{record}, ...]], ...}; bare or nested arrays
// are accepted too.
func flattenRecords(res json.RawMessage) ([]map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(res, &obj) == nil {
		ips, ok := obj["ips"]
		if !ok {
			return nil, fmt.Errorf("sweb: unexpected info result: no \"ips\" field")
		}
		res = ips
	}
	var out []map[string]json.RawMessage
	var walk func(raw json.RawMessage) error
	walk = func(raw json.RawMessage) error {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return fmt.Errorf("sweb: unexpected info result: %w", err)
		}
		for _, el := range arr {
			var m map[string]json.RawMessage
			if json.Unmarshal(el, &m) == nil {
				out = append(out, m)
			} else if err := walk(el); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(res); err != nil {
		return nil, err
	}
	return out, nil
}
