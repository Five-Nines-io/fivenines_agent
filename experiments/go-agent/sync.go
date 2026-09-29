package main

// Synchronizer + SynchronizationQueue: a bounded queue of pre-gzipped
// payloads drained by one goroutine, linear retry backoff, one kept-alive
// connection. http.Client.Timeout bounds the WHOLE request (connect, headers
// and body), which is what http_body.read_capped_body exists to add on top of
// requests' per-socket-operation timeout.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const queueSize = 100

type Synchronizer struct {
	token  string
	queue  chan []byte
	client *http.Client

	mu     sync.Mutex
	config map[string]any
}

func NewSynchronizer(token string) *Synchronizer {
	return &Synchronizer{
		token:  token,
		queue:  make(chan []byte, queueSize),
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func baseURL() string {
	u := apiURL()
	if strings.HasPrefix(u, "localhost") {
		return "http://" + u
	}
	return "https://" + u
}

func gzipJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, 6) // GZIP_LEVEL
	zw.Write(raw)
	zw.Close()
	return buf.Bytes(), nil
}

// Put drops the oldest payload when the queue is full, as the Python queue does.
func (s *Synchronizer) Put(blob []byte) {
	for {
		select {
		case s.queue <- blob:
			return
		default:
			select {
			case <-s.queue:
				logf("info", "Queue full, dropping oldest data")
			default:
			}
		}
	}
}

func (s *Synchronizer) Config() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *Synchronizer) post(ctx context.Context, endpoint string, blob []byte) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL()+endpoint, bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+s.token)
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, body)
	}
	var out map[string]any
	return out, json.Unmarshal(body, &out)
}

// Send posts to /collect with retries and adopts the returned config.
func (s *Synchronizer) Send(ctx context.Context, blob []byte) bool {
	const retries, retryInterval = 3, 5 * time.Second
	for try := 1; try <= retries; try++ {
		res, err := s.post(ctx, "/collect", blob)
		if err == nil {
			// A config is a map: keys this agent does not know are simply never
			// read -- no **kwargs splat, so no TypeError on a new server key.
			if cfg, ok := res["config"].(map[string]any); ok {
				s.mu.Lock()
				s.config = cfg
				s.mu.Unlock()
			}
			return true
		}
		logf("error", "Synchronizer Error: %v; retrying in %s", err, retryInterval*time.Duration(try))
		select {
		case <-ctx.Done():
			return false
		case <-time.After(retryInterval * time.Duration(try)):
		}
	}
	return false
}

func (s *Synchronizer) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case blob := <-s.queue:
			s.Send(ctx, blob)
		}
	}
}
