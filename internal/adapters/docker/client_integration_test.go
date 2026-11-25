package docker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyUnixAPIAndSubscriptionHeaders(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	firstEvent := make(chan struct{})
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutating request")
		}
		switch r.URL.Path {
		case "/version":
			_, _ = fmt.Fprint(w, `{"ApiVersion":"1.99"}`)
		case "/v1.99/containers/json":
			_, _ = fmt.Fprintf(w, `[{"Id":%q}]`, id)
		case "/v1.99/containers/" + id + "/json":
			_, _ = fmt.Fprintf(w, `{"Id":%q,"Config":{"Labels":{}},"State":{"StartedAt":"2026-01-02T03:04:05.123456789Z"}}`, id)
		case "/v1.99/events":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-firstEvent:
				_, _ = fmt.Fprintf(w, "{\"Type\":\"container\",\"Action\":\"start\",\"timeNano\":1767323045123456789,\"Actor\":{\"ID\":%q}}\n", id)
			case <-r.Context().Done():
			}
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := New(ctx, Config{Socket: socket, Timeout: time.Second, MaxRecord: 4096, MaxInventory: 4096, MaxContainers: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stream, err := c.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	close(firstEvent)
	v, err := stream.Next()
	if err != nil || v.Action != "start" || v.StartedAt != nil {
		t.Fatalf("event: %+v %v", v, err)
	}
	items, err := c.Inventory(ctx)
	if err != nil || len(items) != 1 || items[0].StartedAt == nil || items[0].StartedAt.Nanosecond() != 123456789 {
		t.Fatalf("inventory: %+v %v", items, err)
	}
}
