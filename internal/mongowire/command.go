package mongowire

import (
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// CommandName extracts the command name (first key) from a BSON document.
func CommandName(doc bson.Raw) (string, error) {
	elems, err := doc.Elements()
	if err != nil {
		return "", fmt.Errorf("parse BSON elements: %w", err)
	}
	if len(elems) == 0 {
		return "", fmt.Errorf("empty BSON document")
	}
	return elems[0].Key(), nil
}

// CommandDB extracts the "$db" field from a command document.
func CommandDB(doc bson.Raw) string {
	val, err := doc.LookupErr("$db")
	if err != nil {
		return ""
	}
	s, ok := val.StringValueOK()
	if !ok {
		return ""
	}
	return s
}

// BuildSASLStartReply builds the server's response to a saslStart command.
// payload is the SCRAM server-first-message bytes, conversationID identifies the exchange.
func BuildSASLStartReply(requestID int32, payload []byte, conversationID int32) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "conversationId", Value: conversationID},
		{Key: "done", Value: false},
		{Key: "payload", Value: bson.Binary{Data: payload}},
		{Key: "ok", Value: 1.0},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal saslStart reply: %w", err)
	}
	return NewOpMsgMessage(requestID, doc), nil
}

// BuildSASLContinueReply builds the server's final response to a saslContinue command.
// payload is the SCRAM server-final-message bytes.
func BuildSASLContinueReply(requestID int32, payload []byte, conversationID int32) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "conversationId", Value: conversationID},
		{Key: "done", Value: true},
		{Key: "payload", Value: bson.Binary{Data: payload}},
		{Key: "ok", Value: 1.0},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal saslContinue reply: %w", err)
	}
	return NewOpMsgMessage(requestID, doc), nil
}

// BuildSASLStartCommand builds a saslStart command for authenticating to the backend.
func BuildSASLStartCommand(mechanism string, payload []byte, db string) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "saslStart", Value: 1},
		{Key: "mechanism", Value: mechanism},
		{Key: "payload", Value: bson.Binary{Data: payload}},
		{Key: "$db", Value: db},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal saslStart: %w", err)
	}
	return NewOpMsgMessage(0, doc), nil
}

// BuildSASLContinueCommand builds a saslContinue command for authenticating to the backend.
func BuildSASLContinueCommand(payload []byte, conversationID int32, db string) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "saslContinue", Value: 1},
		{Key: "conversationId", Value: conversationID},
		{Key: "payload", Value: bson.Binary{Data: payload}},
		{Key: "$db", Value: db},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal saslContinue: %w", err)
	}
	return NewOpMsgMessage(0, doc), nil
}

// BuildHelloCommand builds a hello command for authenticating to the backend.
func BuildHelloCommand(db string) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "hello", Value: 1},
		{Key: "$db", Value: db},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal hello: %w", err)
	}
	return NewOpMsgMessage(0, doc), nil
}

// BuildErrorReply builds a MongoDB error response.
func BuildErrorReply(requestID int32, code int32, message string) (*Message, error) {
	doc, err := bson.Marshal(bson.D{
		{Key: "ok", Value: 0.0},
		{Key: "errmsg", Value: message},
		{Key: "code", Value: code},
		{Key: "codeName", Value: "AuthenticationFailed"},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal error reply: %w", err)
	}
	return NewOpMsgMessage(requestID, doc), nil
}

// ExtractSASLPayload extracts the binary payload and conversationId from a
// saslStart/saslContinue response document.
func ExtractSASLPayload(doc bson.Raw) (payload []byte, conversationID int32, done bool, err error) {
	var result struct {
		ConversationID int32       `bson:"conversationId"`
		Done           bool        `bson:"done"`
		Payload        bson.Binary `bson:"payload"`
		OK             float64     `bson:"ok"`
	}
	if err := bson.Unmarshal(doc, &result); err != nil {
		return nil, 0, false, fmt.Errorf("unmarshal SASL response: %w", err)
	}
	if result.OK != 1.0 {
		// Try to extract error message.
		errmsg, _ := doc.LookupErr("errmsg")
		if s, ok := errmsg.StringValueOK(); ok {
			return nil, 0, false, fmt.Errorf("SASL error: %s", s)
		}
		return nil, 0, false, fmt.Errorf("SASL command failed (ok=%v)", result.OK)
	}
	return result.Payload.Data, result.ConversationID, result.Done, nil
}
