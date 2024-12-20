package handlers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// Message represents a protocol message with its size and content
type Message struct {
	Size    uint32
	Content []byte
}

// WriteMessage writes a message to a writer with context awareness.
func WriteMessageWithContext(ctx context.Context, w io.Writer, content []byte) error {
	done := make(chan error, 1)
	go func() {
		size := uint32(len(content))

		// Write size as little-endian uint32
		if err := binary.Write(w, binary.LittleEndian, size); err != nil {
			done <- fmt.Errorf("failed to write message size: %w", err)
			return
		}

		// Write content
		if _, err := w.Write(content); err != nil {
			done <- fmt.Errorf("failed to write message content: %w", err)
			return
		}

		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReadMessage reads a message from a reader with context awareness.
func ReadMessageWithContext(ctx context.Context, r io.Reader) (*Message, error) {
	done := make(chan struct {
		msg *Message
		err error
	}, 1)

	go func() {
		var size uint32
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			done <- struct {
				msg *Message
				err error
			}{nil, fmt.Errorf("failed to read message size: %w", err)}
			return
		}

		content := make([]byte, size)
		if _, err := io.ReadFull(r, content); err != nil {
			done <- struct {
				msg *Message
				err error
			}{nil, fmt.Errorf("failed to read message content: %w", err)}
			return
		}

		done <- struct {
			msg *Message
			err error
		}{&Message{Size: size, Content: content}, nil}
	}()

	select {
	case result := <-done:
		return result.msg, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
