package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sin/lanvault/internal/store"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) List() ([]store.ListItem, error) {
	var out []store.ListItem
	if err := c.do("GET", "/v1/secrets", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Get(name string) (string, error) {
	var out struct {
		Value string `json:"value"`
	}
	path := "/v1/secrets/" + url.PathEscape(name)
	if err := c.do("GET", path, nil, &out); err != nil {
		return "", err
	}
	return out.Value, nil
}

func (c *Client) Set(name, value, note string) error {
	body := map[string]string{"value": value, "note": note}
	path := "/v1/secrets/" + url.PathEscape(name)
	return c.do("PUT", path, body, nil)
}

func (c *Client) Delete(name string) error {
	path := "/v1/secrets/" + url.PathEscape(name)
	return c.do("DELETE", path, nil, nil)
}

func (c *Client) Resolve(refs []string) (map[string]string, error) {
	var out struct {
		Values map[string]string `json:"values"`
	}
	if err := c.do("POST", "/v1/resolve", map[string]any{"refs": refs}, &out); err != nil {
		return nil, err
	}
	return out.Values, nil
}

func (c *Client) do(method, path string, body any, dest any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = res.Status
		}
		return fmt.Errorf("api %s: %s", res.Status, msg)
	}
	if dest == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dest)
}
