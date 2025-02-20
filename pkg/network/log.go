// TODO: Temp file for Demo purposes
package network

import (
	"fmt"
	"time"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
)

const (
	// ANSI color codes
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Blue   = "\033[34m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"

	// Unicode symbols
	CheckMark = "✓"
	Arrow     = "→"
	Plus      = "+"
	Download  = "⇩"
)

func LogBlockEvent(timestamp time.Time, eventType string, hash crypto.Hash, epoch jamtime.Epoch, slot jamtime.Timeslot) {
	timeStr := timestamp.Format("15:04:05")
	hashStr := fmt.Sprintf("%x", hash[:5])

	var color, symbol string

	switch eventType {
	case "finalizing":
		color = Green
		symbol = CheckMark
	case "producing", "announcing": // Handle both producing and announcing
		color = Blue
		symbol = Plus
	case "requesting":
		color = Yellow
		symbol = Arrow
	case "imported":
		color = Cyan
		symbol = Download
	}

	// Pad the event type to 10 characters to align output
	paddedEventType := fmt.Sprintf("%-10s", eventType)

	fmt.Printf("[%s] %s%s %s: %s | Epoch: %d | Slot: %d%s\n",
		timeStr,
		color,
		symbol,
		paddedEventType,
		hashStr,
		epoch,
		slot,
		Reset)
}
