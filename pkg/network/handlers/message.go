package handlers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// Message represents a protocol message that includes both size and content.
// The size is encoded as a little-endian uint32 followed by the actual content bytes.
type Message struct {
	// Size is the length of the content in bytes
	Size uint32
	// Content contains the actual message data
	Content []byte
}

// WriteMessageWithContext writes a message to an io.Writer with context cancellation support.
// The message format is:
//   - 4 bytes: content size as little-endian uint32
//   - N bytes: content itself
//
// The write operation can be cancelled via the provided context.
//
// Parameters:
//   - ctx: Context for cancellation
//   - w: Destination writer
//   - content: Message content to write
//
// Returns an error if:
//   - Writing the size fails
//   - Writing the content fails
//   - Context is cancelled during write
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

// ReadMessageWithContext reads a message from an io.Reader with context cancellation support.
// The expected message format is:
//   - 4 bytes: content size as little-endian uint32
//   - N bytes: content itself
//
// The read operation can be cancelled via the provided context.
//
// Parameters:
//   - ctx: Context for cancellation
//   - r: Source reader
//
// Returns:
//   - The read Message and nil if successful
//   - nil and an error if:
//   - Reading the size fails
//   - Reading the content fails
//   - Context is cancelled during read
//   - Size exceeds available memory
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
