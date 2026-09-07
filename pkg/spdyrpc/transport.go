package spdyrpc

import (
	"encoding/json"
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

func newRPCRequest(method string, payload any) (rpcRequest, error) {
	request := rpcRequest{Method: method}
	if payload == nil {
		return request, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return rpcRequest{}, err
	}
	request.Payload = data
	return request, nil
}

func decodeRPCResponse(method string, response rpcResponse, out any) error {
	if !response.OK {
		return fmt.Errorf("RPC request %q failed: %s", method, response.Error)
	}
	if out == nil || len(response.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(response.Payload, out)
}
