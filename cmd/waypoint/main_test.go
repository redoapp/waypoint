package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCheckTCPBackend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()

	if err := checkTCPBackend(context.Background(), address, time.Second); err != nil {
		t.Fatalf("listening backend reported unhealthy: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkTCPBackend(context.Background(), address, 100*time.Millisecond); err == nil {
		t.Fatal("closed backend reported healthy")
	}
}

func TestCheckTCPBackendRejectsNonPositiveTimeout(t *testing.T) {
	if err := checkTCPBackend(context.Background(), "127.0.0.1:1", 0); err == nil {
		t.Fatal("zero timeout should fail")
	}
}
