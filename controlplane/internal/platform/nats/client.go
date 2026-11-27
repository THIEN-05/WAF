package nats

import (
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

type Client interface {
	Publish(subject string, data []byte) error
	Subscribe(subject string, handler func([]byte)) (func() error, error)
	Flush() error
	Close()
}

type connection struct{ conn *nats.Conn }

func Connect(url string) (Client, error) {
	conn, err := nats.Connect(url, nats.Name("waf-control-plane"), nats.Timeout(3*time.Second))
	if err != nil {
		return nil, err
	}
	return &connection{conn: conn}, nil
}

func (c *connection) Publish(subject string, data []byte) error { return c.conn.Publish(subject, data) }
func (c *connection) Flush() error                              { return c.conn.Flush() }
func (c *connection) Close()                                    { c.conn.Close() }
func (c *connection) Subscribe(subject string, handler func([]byte)) (func() error, error) {
	if subject == "" || handler == nil {
		return nil, errors.New("NATS subject and handler are required")
	}
	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) { handler(append([]byte(nil), msg.Data...)) })
	if err != nil {
		return nil, err
	}
	if err = c.conn.Flush(); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	return sub.Unsubscribe, nil
}
