package safrole

const (
	// Custom error codes as defined here https://github.com/w3f/jamtestvectors/blob/master/safrole/safrole.asn#L30

	BadSlot          CustomErrorCode = 0 // Timeslot value must be strictly monotonic.
	UnexpectedTicket CustomErrorCode = 1 // Received a ticket while in epoch's tail.
	BadTicketOrder   CustomErrorCode = 2 // Tickets must be sorted.
	BadTicketProof   CustomErrorCode = 3 // Invalid ticket ring proof.
	BadTicketAttempt CustomErrorCode = 4 // Invalid ticket attempt value.
	Reserved         CustomErrorCode = 5 // Reserved
	DuplicateTicket  CustomErrorCode = 6 // Found a ticket duplicate.
)
