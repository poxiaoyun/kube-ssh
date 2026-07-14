package spdyrpc

import (
	"bytes"
	"fmt"
)

const (
	StreamTypeHeader  = "StreamType"
	StreamTypeControl = "Control"
)

type rpcRequest struct {
	Method  string     `json:"type"`
	Payload RawMessage `json:"payload,omitempty"`
}

type rpcResponse struct {
	OK      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"`
	Payload RawMessage `json:"payload,omitempty"`
}

func newRPCRequest(codec Codec, method string, payload any) (rpcRequest, error) {
	request := rpcRequest{Method: method}
	if payload == nil {
		return request, nil
	}
	data, err := encodePayload(codec, payload)
	if err != nil {
		return rpcRequest{}, err
	}
	request.Payload = data
	return request, nil
}

func decodeRPCResponse(codec Codec, method string, response rpcResponse, out any) error {
	if !response.OK {
		return fmt.Errorf("RPC request %q failed: %s", method, response.Error)
	}
	if out == nil || len(response.Payload) == 0 {
		return nil
	}
	return codec.Decode(bytes.NewReader(response.Payload), out)
}

func encodePayload(codec Codec, payload any) (RawMessage, error) {
	var buffer bytes.Buffer
	if err := codec.Encode(&buffer, payload); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
