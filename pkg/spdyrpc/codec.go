package spdyrpc

import (
	"encoding/json"
	"io"
)

// Codec encodes and decodes one complete value on an RPC stream. A Codec must
// be safe for concurrent use by multiple calls and handlers.
type Codec interface {
	Encode(io.Writer, any) error
	Decode(io.Reader, any) error
}

// JSONCodec encodes RPC values as JSON.
type JSONCodec struct{}

func (JSONCodec) Encode(writer io.Writer, value any) error {
	return json.NewEncoder(writer).Encode(value)
}

func (JSONCodec) Decode(reader io.Reader, value any) error {
	return json.NewDecoder(reader).Decode(value)
}

// RawMessage contains an encoded RPC payload.
type RawMessage = json.RawMessage
