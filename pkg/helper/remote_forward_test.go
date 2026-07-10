package helper

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestRunRuntimeRemoteForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	toHelperReader, toHelperWriter := io.Pipe()
	fromHelperReader, fromHelperWriter := io.Pipe()
	defer toHelperReader.Close()
	defer toHelperWriter.Close()
	defer fromHelperReader.Close()
	defer fromHelperWriter.Close()

	done := make(chan error, 1)
	go func() {
		done <- RunRuntime(ctx, toHelperReader, fromHelperWriter)
	}()

	client, err := NewRuntimeClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewRuntimeClient() error = %v", err)
	}
	defer client.Close()

	forward, err := client.RemoteForward(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("RemoteForward() error = %v", err)
	}

	if forward.ActualPort() == 0 {
		t.Fatal("ActualPort() = 0")
	}

	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(forward.ActualPort()), 10)), time.Second)
	if err != nil {
		t.Fatalf("Dial remote-forward listener error = %v", err)
	}
	defer tcpConn.Close()

	acceptCtx, acceptCancel := context.WithTimeout(ctx, time.Second)
	defer acceptCancel()
	stream, info, err := forward.Accept(acceptCtx)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer stream.Close()

	if info.OriginHost == "" {
		t.Fatal("OriginHost is empty")
	}
	if info.OriginPort == 0 {
		t.Fatal("OriginPort is 0")
	}

	if _, err := tcpConn.Write([]byte("from tcp")); err != nil {
		t.Fatalf("write tcp side: %v", err)
	}
	if got := readExactly(t, stream, len("from tcp")); got != "from tcp" {
		t.Fatalf("stream read = %q, want %q", got, "from tcp")
	}

	if _, err := stream.Write([]byte("from stream")); err != nil {
		t.Fatalf("write stream side: %v", err)
	}
	_ = tcpConn.SetReadDeadline(time.Now().Add(time.Second))
	if got := readExactly(t, tcpConn, len("from stream")); got != "from stream" {
		t.Fatalf("tcp read = %q, want %q", got, "from stream")
	}

	if err := forward.Cancel(ctx); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if _, _, err := forward.Accept(context.Background()); err == nil {
		t.Fatal("Accept() after Cancel succeeded")
	}

	if _, err := tcpConn.Write([]byte("after cancel")); err != nil {
		t.Fatalf("write tcp side after cancel: %v", err)
	}
	if got := readExactly(t, stream, len("after cancel")); got != "after cancel" {
		t.Fatalf("stream read after cancel = %q, want %q", got, "after cancel")
	}
	if _, err := stream.Write([]byte("still active")); err != nil {
		t.Fatalf("write stream side after cancel: %v", err)
	}
	_ = tcpConn.SetReadDeadline(time.Now().Add(time.Second))
	if got := readExactly(t, tcpConn, len("still active")); got != "still active" {
		t.Fatalf("tcp read after cancel = %q, want %q", got, "still active")
	}

	_ = stream.Close()
	_ = tcpConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunRuntime() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop after active stream closed")
	}

	cancel()
}

func TestRunRuntimeRemoteForwardMultipleBinds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	toHelperReader, toHelperWriter := io.Pipe()
	fromHelperReader, fromHelperWriter := io.Pipe()
	defer toHelperReader.Close()
	defer toHelperWriter.Close()
	defer fromHelperReader.Close()
	defer fromHelperWriter.Close()

	done := make(chan error, 1)
	go func() {
		done <- RunRuntime(ctx, toHelperReader, fromHelperWriter)
	}()

	client, err := NewRuntimeClient(ctx, toHelperWriter, fromHelperReader)
	if err != nil {
		t.Fatalf("NewRuntimeClient() error = %v", err)
	}
	defer client.Close()

	first, err := client.RemoteForward(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("first RemoteForward() error = %v", err)
	}
	second, err := client.RemoteForward(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("second RemoteForward() error = %v", err)
	}
	if first.ActualPort() == second.ActualPort() {
		t.Fatalf("remote forwards used same port %d", first.ActualPort())
	}

	firstTCP := dialForward(t, first.ActualPort())
	defer firstTCP.Close()
	secondTCP := dialForward(t, second.ActualPort())
	defer secondTCP.Close()

	firstStream, firstInfo, err := first.Accept(ctx)
	if err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	defer firstStream.Close()
	secondStream, secondInfo, err := second.Accept(ctx)
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	defer secondStream.Close()

	if firstInfo.Bind == secondInfo.Bind {
		t.Fatalf("remote-forward binds are equal: %q", firstInfo.Bind)
	}

	if _, err := firstTCP.Write([]byte("first")); err != nil {
		t.Fatalf("write first tcp side: %v", err)
	}
	if got := readExactly(t, firstStream, len("first")); got != "first" {
		t.Fatalf("first stream read = %q, want first", got)
	}
	if _, err := secondTCP.Write([]byte("second")); err != nil {
		t.Fatalf("write second tcp side: %v", err)
	}
	if got := readExactly(t, secondStream, len("second")); got != "second" {
		t.Fatalf("second stream read = %q, want second", got)
	}

	if err := first.Cancel(ctx); err != nil {
		t.Fatalf("first Cancel() error = %v", err)
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(first.ActualPort()), 10)), 100*time.Millisecond); err == nil {
		t.Fatal("dial first listener after Cancel succeeded")
	}

	thirdTCP := dialForward(t, second.ActualPort())
	defer thirdTCP.Close()
	thirdStream, _, err := second.Accept(ctx)
	if err != nil {
		t.Fatalf("second Accept() after first Cancel error = %v", err)
	}
	defer thirdStream.Close()
	if _, err := thirdTCP.Write([]byte("still-second")); err != nil {
		t.Fatalf("write third tcp side: %v", err)
	}
	if got := readExactly(t, thirdStream, len("still-second")); got != "still-second" {
		t.Fatalf("third stream read = %q, want still-second", got)
	}

	if err := second.Cancel(ctx); err != nil {
		t.Fatalf("second Cancel() error = %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("RunRuntime() stopped before active streams closed: %v", err)
	default:
	}
	if _, err := firstTCP.Write([]byte("after-both-cancel")); err != nil {
		t.Fatalf("write first tcp side after both cancels: %v", err)
	}
	if got := readExactly(t, firstStream, len("after-both-cancel")); got != "after-both-cancel" {
		t.Fatalf("first stream read after both cancels = %q, want after-both-cancel", got)
	}
	_ = firstStream.Close()
	_ = secondStream.Close()
	_ = thirdStream.Close()
	_ = firstTCP.Close()
	_ = secondTCP.Close()
	_ = thirdTCP.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunRuntime() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop after all forwards canceled")
	}
}

func TestRemoteForwardCancelIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, done := startRuntimeClient(t, ctx)
	defer client.Close()

	forward, err := client.RemoteForward(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("RemoteForward() error = %v", err)
	}
	if err := forward.Cancel(ctx); err != nil {
		t.Fatalf("first Cancel() error = %v", err)
	}
	if err := forward.Cancel(ctx); err != nil {
		t.Fatalf("second Cancel() error = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunRuntime() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop")
	}
}

func TestRemoteForwardAcceptReturnsWhenClientCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, done := startRuntimeClient(t, ctx)

	forward, err := client.RemoteForward(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("RemoteForward() error = %v", err)
	}

	acceptDone := make(chan error, 1)
	go func() {
		_, _, err := forward.Accept(context.Background())
		acceptDone <- err
	}()

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-acceptDone:
		if err == nil {
			t.Fatal("Accept() error = nil after client close")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() did not return after client close")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRuntime() did not stop")
	}
}

func TestRemoteForwardDispatchFallsBackToRequestedBind(t *testing.T) {
	runtime := &RuntimeClient{
		conn:   newFakeRuntimeConn(),
		closed: make(chan struct{}),
	}
	client := newRemoteForwardClient(runtime)
	forward := newRemoteForward(client, "127.0.0.1:2222")
	if !client.add("127.0.0.1:2222", forward) {
		t.Fatal("add() = false")
	}

	stream := newFakeStream(RemoteForwardHeaders("127.0.0.1:3333", "127.0.0.1:2222", "127.0.0.1", "5151"))
	incoming, err := remoteForwardIncomingFromStream(stream)
	if err != nil {
		t.Fatalf("remoteForwardIncomingFromStream() error = %v", err)
	}
	client.dispatch(incoming)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, info, err := forward.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer got.Close()
	if info.Bind != "127.0.0.1:3333" {
		t.Fatalf("Bind = %q, want 127.0.0.1:3333", info.Bind)
	}
	if info.RequestedBind != "127.0.0.1:2222" {
		t.Fatalf("RequestedBind = %q, want 127.0.0.1:2222", info.RequestedBind)
	}
	if stream.closed {
		t.Fatal("stream was closed")
	}
}

func TestRemoteForwardRekeyDoesNotResurrectRemovedForward(t *testing.T) {
	runtime := &RuntimeClient{
		conn:   newFakeRuntimeConn(),
		closed: make(chan struct{}),
	}
	client := newRemoteForwardClient(runtime)
	forward := newRemoteForward(client, "127.0.0.1:0")
	if !client.add("127.0.0.1:0", forward) {
		t.Fatal("add() = false")
	}

	client.removeIfMatch("127.0.0.1:0", forward)
	if client.rekey("127.0.0.1:0", "127.0.0.1:3333", forward) {
		t.Fatal("rekey() = true after forward was removed")
	}
	if got := len(client.forwards); got != 0 {
		t.Fatalf("forward registry size = %d, want 0", got)
	}
}

func TestRemoteForwardCancelRemovesRequestedAndActualBinds(t *testing.T) {
	runtime := &RuntimeClient{
		conn:   newFakeRuntimeConn(),
		closed: make(chan struct{}),
	}
	client := newRemoteForwardClient(runtime)
	forward := newRemoteForward(client, "127.0.0.1:0")
	forward.actualBind = "127.0.0.1:3333"

	client.forwards["127.0.0.1:0"] = forward
	client.forwards["127.0.0.1:3333"] = forward

	if err := forward.Cancel(context.Background()); err == nil {
		t.Fatal("Cancel() error = nil, want fake runtime error")
	}
	if got := len(client.forwards); got != 0 {
		t.Fatalf("forward registry size = %d, want 0", got)
	}
}

func TestRemoteForwardDeliverAfterCloseClosesStream(t *testing.T) {
	runtime := &RuntimeClient{
		conn:   newFakeRuntimeConn(),
		closed: make(chan struct{}),
	}
	client := newRemoteForwardClient(runtime)
	forward := newRemoteForward(client, "127.0.0.1:2222")
	forward.closeLocal()

	stream := newFakeStream(RemoteForwardHeaders("127.0.0.1:2222", "127.0.0.1:2222", "127.0.0.1", "5151"))
	incoming, err := remoteForwardIncomingFromStream(stream)
	if err != nil {
		t.Fatalf("remoteForwardIncomingFromStream() error = %v", err)
	}
	forward.deliver(incoming)
	if !stream.closed {
		t.Fatal("stream was not closed")
	}
	if !runtime.conn.(*fakeRuntimeConn).removed(stream) {
		t.Fatal("stream was not removed")
	}
}
