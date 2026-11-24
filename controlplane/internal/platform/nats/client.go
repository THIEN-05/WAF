package nats

import (
	"time"

	"github.com/nats-io/nats.go"
)

type Client interface {
	Publish(subject string, data []byte) error
	Flush() error
	Close()
}

func Connect(url string) (Client, error) {
	return nats.Connect(url, nats.Name("waf-control-plane"), nats.Timeout(3*time.Second))
}
