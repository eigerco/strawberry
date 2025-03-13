package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWriter is a custom io.Writer that can be configured to fail
type mockWriter struct {
	buffer      *bytes.Buffer
	failSize    bool          // Will fail on the first write (size) if true
	failWrite   bool          // Will fail on the second write (content) if true
	writeDelay  time.Duration // To simulate slow writes
	sizeWritten bool          // Track if size has been written
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if !m.sizeWritten && m.failSize {
		m.sizeWritten = true
		return 0, errors.New("mock size write error")
	}

	if m.sizeWritten && m.failWrite {
		return 0, errors.New("mock content write error")
	}

	if m.writeDelay > 0 {
		time.Sleep(m.writeDelay)
	}

	m.sizeWritten = true
	return m.buffer.Write(p)
}

// mockReader is a custom io.Reader that can be configured to fail
type mockReader struct {
	buffer      *bytes.Buffer
	failSize    bool
	failRead    bool
	readDelay   time.Duration // To simulate slow reads
	sizeRead    bool          // Track if size has been read
	contentRead bool          // Track if content has been read
	bytesRead   int           // Track total bytes read
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	// Check if this is the size read (first 4 bytes)
	if !m.sizeRead && len(p) == 4 {
		m.sizeRead = true
		if m.failSize {
			return 0, errors.New("mock size read error")
		}
	} else if m.sizeRead && !m.contentRead {
		// This is a content read
		m.contentRead = true
		if m.failRead {
			return 0, errors.New("mock content read error")
		}
	}

	if m.readDelay > 0 {
		time.Sleep(m.readDelay)
	}

	n, err = m.buffer.Read(p)
	m.bytesRead += n
	return n, err
}

func TestWriteMessageWithContext(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		content := []byte("test message")
		buffer := &bytes.Buffer{}
		ctx := context.Background()

		err := WriteMessageWithContext(ctx, buffer, content)

		require.NoError(t, err)
		assert.Equal(t, uint32(12), binary.LittleEndian.Uint32(buffer.Bytes()[:4]), "Size should be 11 (length of 'test message')")
		assert.Equal(t, content, buffer.Bytes()[4:], "Content should match the input")
	})

	t.Run("write size error", func(t *testing.T) {
		content := []byte("test message")
		writer := &mockWriter{
			buffer:   &bytes.Buffer{},
			failSize: true,
		}
		ctx := context.Background()

		err := WriteMessageWithContext(ctx, writer, content)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write message size")
	})

	t.Run("write content error", func(t *testing.T) {
		content := []byte("test message")
		writer := &mockWriter{
			buffer:      &bytes.Buffer{},
			failWrite:   true,
			sizeWritten: false, // Make sure we fail on content write, not size write
		}
		ctx := context.Background()

		err := WriteMessageWithContext(ctx, writer, content)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write message content")
	})

	t.Run("context cancellation", func(t *testing.T) {
		content := []byte("test message")
		writer := &mockWriter{
			buffer:     &bytes.Buffer{},
			writeDelay: 100 * time.Millisecond,
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel the context after a brief delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := WriteMessageWithContext(ctx, writer, content)

		require.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

func TestReadMessageWithContext(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		content := []byte("test message")
		buffer := &bytes.Buffer{}

		// Write the size and content to the buffer
		err := binary.Write(buffer, binary.LittleEndian, uint32(len(content)))
		require.NoError(t, err)
		buffer.Write(content)
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, buffer)

		require.NoError(t, err)
		require.NotNil(t, msg)
		assert.Equal(t, uint32(len(content)), msg.Size)
		assert.Equal(t, content, msg.Content)
	})

	t.Run("read size error", func(t *testing.T) {
		reader := &mockReader{
			buffer:   &bytes.Buffer{},
			failSize: true,
		}
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, reader)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Contains(t, err.Error(), "failed to read message size")
	})

	t.Run("read content error", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		// Write just the size but no content
		err := binary.Write(buffer, binary.LittleEndian, uint32(10))
		require.NoError(t, err)
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, buffer)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Contains(t, err.Error(), "failed to read message content")
	})

	t.Run("read content mock error", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		err := binary.Write(buffer, binary.LittleEndian, uint32(10))
		require.NoError(t, err)
		buffer.Write(make([]byte, 10)) // Add some content
		reader := &mockReader{
			buffer:   buffer,
			failRead: true,
		}
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, reader)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Contains(t, err.Error(), "failed to read message content")
	})

	t.Run("context cancellation", func(t *testing.T) {
		content := []byte("test message")
		buffer := &bytes.Buffer{}

		// Write the size and content to the buffer
		err := binary.Write(buffer, binary.LittleEndian, uint32(len(content)))
		require.NoError(t, err)
		buffer.Write(content)
		reader := &mockReader{
			buffer:    buffer,
			readDelay: 100 * time.Millisecond,
		}
		ctx, cancel := context.WithCancel(context.Background())
		// Cancel the context after a brief delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		msg, err := ReadMessageWithContext(ctx, reader)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("zero size message", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		// Write zero size
		err := binary.Write(buffer, binary.LittleEndian, uint32(0))
		require.NoError(t, err)
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, buffer)

		require.NoError(t, err)
		require.NotNil(t, msg)
		assert.Equal(t, uint32(0), msg.Size)
		assert.Equal(t, []byte{}, msg.Content)
	})

	t.Run("partial read", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		// Write size for 10 bytes
		err := binary.Write(buffer, binary.LittleEndian, uint32(10))
		require.NoError(t, err)
		// But only write 5 bytes
		buffer.Write([]byte("hello"))
		ctx := context.Background()

		msg, err := ReadMessageWithContext(ctx, buffer)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Contains(t, err.Error(), "failed to read message content")
	})

	t.Run("timeout context", func(t *testing.T) {
		content := []byte("test message")
		buffer := &bytes.Buffer{}
		// Write the size and content to the buffer
		err := binary.Write(buffer, binary.LittleEndian, uint32(len(content)))
		require.NoError(t, err)
		buffer.Write(content)
		reader := &mockReader{
			buffer:    buffer,
			readDelay: 100 * time.Millisecond,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		msg, err := ReadMessageWithContext(ctx, reader)

		require.Error(t, err)
		assert.Nil(t, msg)
		assert.Equal(t, context.DeadlineExceeded, err)
	})
}

// TestIntegration_ReadWriteMessage tests both functions together
func TestIntegration_ReadWriteMessage(t *testing.T) {
	t.Run("write then read", func(t *testing.T) {
		content := []byte("test integration message")
		buffer := &bytes.Buffer{}
		ctx := context.Background()

		// Write
		err := WriteMessageWithContext(ctx, buffer, content)
		require.NoError(t, err)

		// Read
		msg, err := ReadMessageWithContext(ctx, buffer)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, msg)
		assert.Equal(t, uint32(len(content)), msg.Size)
		assert.Equal(t, content, msg.Content)
	})

	t.Run("multiple messages", func(t *testing.T) {
		messages := [][]byte{
			[]byte("first message"),
			[]byte("second message"),
			[]byte("third message with longer content"),
		}
		buffer := &bytes.Buffer{}
		ctx := context.Background()

		// Write all messages
		for _, content := range messages {
			err := WriteMessageWithContext(ctx, buffer, content)
			require.NoError(t, err)
		}

		// Read all messages
		for _, expectedContent := range messages {
			msg, err := ReadMessageWithContext(ctx, buffer)

			// Assert each message
			require.NoError(t, err)
			require.NotNil(t, msg)
			assert.Equal(t, uint32(len(expectedContent)), msg.Size)
			assert.Equal(t, expectedContent, msg.Content)
		}

		// Verify we've read everything
		assert.Equal(t, 0, buffer.Len())
	})
}
