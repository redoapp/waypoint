package mongowire

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// DummyPassword is the well-known password that MongoDB clients may use when
// connecting through waypoint with credentials. Tailscale identity is the real
// credential; this password exists only to satisfy the SCRAM protocol.
// Clients can also connect with NO credentials (preferred).
const DummyPassword = "waypoint"

// ClientHello contains the parsed client hello message, before the proxy replies.
type ClientHello struct {
	Message  *Message // the raw hello message
	Doc      bson.Raw // parsed hello document
	IsLegacy bool     // true if sent as OP_QUERY (legacy isMaster)
	AuthDB   string   // authentication database (usually "admin")
	Username string   // from saslSupportedMechs or SCRAM, empty if no auth
	SpecAuth bson.Raw // speculativeAuthenticate document, nil if not present
}

// ClientHandshakeResult contains information extracted from the client's handshake.
type ClientHandshakeResult struct {
	AuthDB   string // the authentication database (usually "admin")
	Username string // the username from the SCRAM exchange (empty if no auth)

	// FirstCommand is non-nil when the client connected without credentials.
	// The proxy must forward this message to the backend before starting relay.
	FirstCommand *Message
}

// ReadClientHello reads and parses the client's initial hello/isMaster message
// without sending a reply. The caller should use CompleteHandshake to send
// the reply after obtaining the backend's real hello response.
func ReadClientHello(clientConn net.Conn) (*ClientHello, error) {
	hello := &ClientHello{AuthDB: "admin"}

	msg, err := ReadMessage(clientConn)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	hello.Message = msg

	var helloDoc bson.Raw
	switch msg.Header.OpCode {
	case OpMsg:
		_, helloDoc, err = ParseOpMsgBody(msg.Body)
		if err != nil {
			return nil, fmt.Errorf("parse client hello OP_MSG: %w", err)
		}
	case OpQuery:
		hello.IsLegacy = true
		helloDoc, err = ParseOpQueryBody(msg.Body)
		if err != nil {
			return nil, fmt.Errorf("parse client hello OP_QUERY: %w", err)
		}
	default:
		return nil, fmt.Errorf("expected OP_MSG or OP_QUERY, got opcode %d", msg.Header.OpCode)
	}
	hello.Doc = helloDoc

	cmdName, err := CommandName(helloDoc)
	if err != nil {
		return nil, fmt.Errorf("extract command: %w", err)
	}
	switch strings.ToLower(cmdName) {
	case "hello", "ismaster", "ismasteraliased":
	default:
		return nil, fmt.Errorf("expected hello/isMaster, got %q", cmdName)
	}

	if db := CommandDB(helloDoc); db != "" {
		hello.AuthDB = db
	}

	// Extract username from saslSupportedMechs ("db.username" format).
	if val, err := helloDoc.LookupErr("saslSupportedMechs"); err == nil {
		if s, ok := val.StringValueOK(); ok {
			if idx := strings.Index(s, "."); idx >= 0 {
				hello.Username = s[idx+1:]
			}
		}
	}

	// Check for speculative authentication (MongoDB 4.4+ with credentials).
	if val, err := helloDoc.LookupErr("speculativeAuthenticate"); err == nil {
		if d, ok := val.DocumentOK(); ok {
			hello.SpecAuth = d
		}
	}

	return hello, nil
}

// CompleteHandshake sends the hello reply and handles optional SCRAM-SHA-256.
// backendHelloDoc is the backend's real hello response used for capabilities
// and topology. proxyAddr is used to rewrite topology fields (hosts, me, etc.).
//
// Supports two client paths:
//   - No credentials (preferred): sends hello reply, reads next message.
//     If it's a regular command, buffers it in FirstCommand.
//   - With credentials: full SCRAM-SHA-256 exchange using DummyPassword.
func CompleteHandshake(clientConn net.Conn, hello *ClientHello, backendHelloDoc bson.Raw, proxyAddr string) (*ClientHandshakeResult, error) {
	return CompleteHandshakeWithTopologyMap(clientConn, hello, backendHelloDoc, proxyAddr, nil)
}

// CompleteHandshakeWithTopologyMap is like CompleteHandshake, but rewrites
// each known backend replica-set member to its configured proxy address.
func CompleteHandshakeWithTopologyMap(clientConn net.Conn, hello *ClientHello, backendHelloDoc bson.Raw, proxyAddr string, topologyMap map[string]string) (*ClientHandshakeResult, error) {
	result := &ClientHandshakeResult{
		AuthDB:   hello.AuthDB,
		Username: hello.Username,
	}

	if hello.SpecAuth != nil {
		// Client has credentials and is doing speculative auth.
		srv := NewSCRAMServer()
		return handleSpecAuth(clientConn, hello, srv, backendHelloDoc, proxyAddr, topologyMap, result)
	}

	// No speculative auth. Send hello reply and see what the client does next.
	return handlePostHello(clientConn, hello, backendHelloDoc, proxyAddr, topologyMap, result)
}

// HandleClientHandshake is a convenience wrapper that uses a fabricated hello
// response. Prefer ReadClientHello + CompleteHandshake with the backend's real
// hello for production use.
func HandleClientHandshake(clientConn net.Conn) (*ClientHandshakeResult, error) {
	hello, err := ReadClientHello(clientConn)
	if err != nil {
		return nil, err
	}
	fabricated, err := buildFabricatedHelloDoc()
	if err != nil {
		return nil, err
	}
	return CompleteHandshake(clientConn, hello, fabricated, "")
}

// handlePostHello sends the hello reply and reads the next message to determine
// whether the client is authenticating or sending a regular command.
func handlePostHello(clientConn net.Conn, hello *ClientHello, backendHelloDoc bson.Raw, proxyAddr string, topologyMap map[string]string, result *ClientHandshakeResult) (*ClientHandshakeResult, error) {
	if err := sendHelloReply(clientConn, hello, backendHelloDoc, proxyAddr, topologyMap); err != nil {
		return nil, err
	}

	// Read next message — could be saslStart (auth) or a regular command (no auth).
	nextMsg, err := ReadMessage(clientConn)
	if err != nil {
		return nil, fmt.Errorf("read post-hello message: %w", err)
	}
	if nextMsg.Header.OpCode != OpMsg {
		return nil, fmt.Errorf("expected OP_MSG, got opcode %d", nextMsg.Header.OpCode)
	}

	_, nextDoc, err := ParseOpMsgBody(nextMsg.Body)
	if err != nil {
		return nil, fmt.Errorf("parse post-hello: %w", err)
	}

	nextCmdName, _ := CommandName(nextDoc)

	if strings.ToLower(nextCmdName) == "saslstart" {
		// Client is authenticating with credentials.
		srv := NewSCRAMServer()
		return handleSASLStart(clientConn, nextMsg, nextDoc, srv, result)
	}

	// Client sent a regular command without authenticating.
	// Buffer it — the proxy will forward it after backend auth completes.
	result.FirstCommand = nextMsg
	return result, nil
}

// handleSASLStart handles a standalone saslStart (non-speculative auth path).
func handleSASLStart(clientConn net.Conn, startMsg *Message, startDoc bson.Raw, srv *SCRAMServer, result *ClientHandshakeResult) (*ClientHandshakeResult, error) {
	var startCmd struct {
		Mechanism string      `bson:"mechanism"`
		Payload   bson.Binary `bson:"payload"`
	}
	if err := bson.Unmarshal(startDoc, &startCmd); err != nil {
		return nil, fmt.Errorf("unmarshal saslStart: %w", err)
	}
	if startCmd.Mechanism != "SCRAM-SHA-256" {
		return nil, fmt.Errorf("unsupported mechanism %q", startCmd.Mechanism)
	}

	clientFirst := string(startCmd.Payload.Data)
	clientNonce, username := parseClientFirst(clientFirst)
	if clientNonce == "" {
		return nil, fmt.Errorf("no nonce in client-first-message")
	}
	if username != "" && result.Username == "" {
		result.Username = username
	}

	serverFirst := srv.buildServerFirst(clientNonce)

	startReply, err := BuildSASLStartReply(startMsg.Header.RequestID, []byte(serverFirst), srv.conversationID)
	if err != nil {
		return nil, err
	}
	if err := WriteMessage(clientConn, startReply); err != nil {
		return nil, fmt.Errorf("send saslStart reply: %w", err)
	}

	return readAndCompleteSASL(clientConn, srv, clientFirst, serverFirst, result)
}

// handleSpecAuth handles the speculative authentication path.
func handleSpecAuth(clientConn net.Conn, hello *ClientHello, srv *SCRAMServer, backendHelloDoc bson.Raw, proxyAddr string, topologyMap map[string]string, result *ClientHandshakeResult) (*ClientHandshakeResult, error) {
	var specCmd struct {
		Mechanism string      `bson:"mechanism"`
		Payload   bson.Binary `bson:"payload"`
		DB        string      `bson:"$db"`
	}
	if err := bson.Unmarshal(hello.SpecAuth, &specCmd); err != nil {
		return nil, fmt.Errorf("unmarshal speculative auth: %w", err)
	}
	if specCmd.DB != "" {
		result.AuthDB = specCmd.DB
	}
	if specCmd.Mechanism != "SCRAM-SHA-256" {
		return nil, fmt.Errorf("unsupported mechanism %q; only SCRAM-SHA-256 supported", specCmd.Mechanism)
	}

	clientFirst := string(specCmd.Payload.Data)
	clientNonce, username := parseClientFirst(clientFirst)
	if clientNonce == "" {
		return nil, fmt.Errorf("no nonce in client-first-message")
	}
	if username != "" && result.Username == "" {
		result.Username = username
	}

	serverFirst := srv.buildServerFirst(clientNonce)

	specReply, err := bson.Marshal(bson.D{
		{Key: "conversationId", Value: srv.conversationID},
		{Key: "done", Value: false},
		{Key: "payload", Value: bson.Binary{Data: []byte(serverFirst)}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal spec reply: %w", err)
	}

	// Build hello reply from backend's real capabilities + topology rewriting.
	helloReplyDoc, err := buildClientHelloReply(backendHelloDoc, proxyAddr, topologyMap)
	if err != nil {
		return nil, fmt.Errorf("build hello reply: %w", err)
	}

	// Inject the speculativeAuthenticate response.
	var d bson.D
	if err := bson.Unmarshal(helloReplyDoc, &d); err != nil {
		return nil, fmt.Errorf("unmarshal hello reply: %w", err)
	}
	d = append(d, bson.E{Key: "speculativeAuthenticate", Value: bson.Raw(specReply)})

	finalDoc, err := bson.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal hello reply with spec auth: %w", err)
	}

	if err := WriteMessage(clientConn, NewOpMsgMessage(hello.Message.Header.RequestID, finalDoc)); err != nil {
		return nil, fmt.Errorf("send hello reply: %w", err)
	}

	return readAndCompleteSASL(clientConn, srv, clientFirst, serverFirst, result)
}

// readAndCompleteSASL reads the client's saslContinue, verifies the proof
// using DummyPassword, and sends the server-final-message.
func readAndCompleteSASL(clientConn net.Conn, srv *SCRAMServer, clientFirst, serverFirst string, result *ClientHandshakeResult) (*ClientHandshakeResult, error) {
	contMsg, err := ReadMessage(clientConn)
	if err != nil {
		return nil, fmt.Errorf("read saslContinue: %w", err)
	}
	_, contDoc, err := ParseOpMsgBody(contMsg.Body)
	if err != nil {
		return nil, fmt.Errorf("parse saslContinue: %w", err)
	}

	var contCmd struct {
		ConversationID int32       `bson:"conversationId"`
		Payload        bson.Binary `bson:"payload"`
	}
	if err := bson.Unmarshal(contDoc, &contCmd); err != nil {
		return nil, fmt.Errorf("unmarshal saslContinue: %w", err)
	}

	clientFinal := string(contCmd.Payload.Data)
	clientFinalWithoutProof, proof, err := parseClientFinal(clientFinal)
	if err != nil {
		return nil, err
	}

	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	saltedPassword := scramHi([]byte(DummyPassword), srv.salt, srv.iterations)
	clientKey := scramHMAC(saltedPassword, []byte("Client Key"))
	storedKey := scramSHA256(clientKey)
	clientSignature := scramHMAC(storedKey, []byte(authMessage))
	expectedProof := scramXOR(clientKey, clientSignature)

	if !hmac.Equal(proof, expectedProof) {
		errReply, _ := BuildErrorReply(contMsg.Header.RequestID, 18,
			fmt.Sprintf("authentication failed: use password %q or connect without credentials", DummyPassword))
		WriteMessage(clientConn, errReply)
		return nil, fmt.Errorf("client proof mismatch: use password %q or connect without credentials", DummyPassword)
	}

	serverKey := scramHMAC(saltedPassword, []byte("Server Key"))
	serverSignature := scramHMAC(serverKey, []byte(authMessage))
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSignature)

	contReply, err := BuildSASLContinueReply(contMsg.Header.RequestID, []byte(serverFinal), srv.conversationID)
	if err != nil {
		return nil, fmt.Errorf("build server-final: %w", err)
	}
	if err := WriteMessage(clientConn, contReply); err != nil {
		return nil, fmt.Errorf("send server-final: %w", err)
	}

	return result, nil
}

// sendHelloReply sends a hello reply in either OP_MSG or OP_REPLY format,
// using the backend's real hello document with topology rewriting.
func sendHelloReply(conn net.Conn, hello *ClientHello, backendHelloDoc bson.Raw, proxyAddr string, topologyMap map[string]string) error {
	replyDoc, err := buildClientHelloReply(backendHelloDoc, proxyAddr, topologyMap)
	if err != nil {
		return fmt.Errorf("build hello reply: %w", err)
	}

	if hello.IsLegacy {
		return WriteMessage(conn, NewOpReplyMessage(hello.Message.Header.RequestID, replyDoc))
	}
	return WriteMessage(conn, NewOpMsgMessage(hello.Message.Header.RequestID, replyDoc))
}

// buildClientHelloReply takes the backend's real hello response and prepares
// it for the client. It rewrites topology fields to the proxy address, ensures
// SCRAM-SHA-256 is advertised, and strips compression.
func buildClientHelloReply(backendHelloDoc bson.Raw, proxyAddr string, topologyMap map[string]string) (bson.Raw, error) {
	var d bson.D
	if err := bson.Unmarshal(backendHelloDoc, &d); err != nil {
		return nil, fmt.Errorf("unmarshal backend hello: %w", err)
	}

	// Rewrite topology fields, strip compression, ensure auth mechs.
	hasSASLMechs := false
	for i := range d {
		key := strings.ToLower(d[i].Key)

		// Rewrite topology array fields.
		for _, tf := range topologyFieldNames {
			if key == tf {
				if arr, ok := d[i].Value.(bson.A); ok && proxyAddr != "" {
					for j := range arr {
						if s, ok := arr[j].(string); ok {
							arr[j] = rewriteTopologyAddr(s, proxyAddr, topologyMap)
						}
					}
					d[i].Value = arr
				}
				break
			}
		}

		// Rewrite singular topology fields.
		if (key == "me" || key == "primary") && proxyAddr != "" {
			if s, ok := d[i].Value.(string); ok {
				d[i].Value = rewriteTopologyAddr(s, proxyAddr, topologyMap)
			}
		}

		// Override saslSupportedMechs to only advertise what we support.
		if key == "saslsupportedmechs" {
			d[i].Value = bson.A{"SCRAM-SHA-256"}
			hasSASLMechs = true
		}

		// Strip compression — the proxy doesn't support it.
		if key == "compression" {
			d[i].Value = bson.A{}
		}
	}

	if !hasSASLMechs {
		d = append(d, bson.E{Key: "saslSupportedMechs", Value: bson.A{"SCRAM-SHA-256"}})
	}

	return bson.Marshal(d)
}

// topologyFieldNames reuses the topology.go field list for consistency.
// Both the handshake hello reply and the relay-path rewriter must agree
// on which fields to rewrite.
var topologyFieldNames = topologyFields

// buildFabricatedHelloDoc creates a minimal hello response for use when
// the backend's real hello is not available (e.g., testing).
func buildFabricatedHelloDoc() (bson.Raw, error) {
	return bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "maxBsonObjectSize", Value: 16777216},
		{Key: "maxMessageSizeBytes", Value: 48000000},
		{Key: "maxWriteBatchSize", Value: 100000},
		{Key: "minWireVersion", Value: 0},
		{Key: "maxWireVersion", Value: 17}, // conservative: MongoDB 6.0
		{Key: "saslSupportedMechs", Value: bson.A{"SCRAM-SHA-256"}},
		{Key: "ok", Value: 1.0},
	})
}

// SendErrorAsHelloReply sends an error in the appropriate format based on
// whether the client sent a legacy OP_QUERY or modern OP_MSG hello.
// Use this for errors that occur after reading the client hello but before
// completing the handshake.
func SendErrorAsHelloReply(conn net.Conn, hello *ClientHello, code int32, message string) {
	doc, err := bson.Marshal(bson.D{
		{Key: "ok", Value: 0.0},
		{Key: "errmsg", Value: message},
		{Key: "code", Value: code},
		{Key: "codeName", Value: "AuthenticationFailed"},
	})
	if err != nil {
		return
	}

	if hello.IsLegacy {
		WriteMessage(conn, NewOpReplyMessage(hello.Message.Header.RequestID, doc))
	} else {
		WriteMessage(conn, NewOpMsgMessage(hello.Message.Header.RequestID, doc))
	}
}

// buildServerFirst generates the server-first-message for the given client nonce.
func (s *SCRAMServer) buildServerFirst(clientNonce string) string {
	return fmt.Sprintf("r=%s%s,s=%s,i=%d",
		clientNonce, s.serverNonce,
		base64.StdEncoding.EncodeToString(s.salt),
		s.iterations,
	)
}

// parseClientFirst extracts the nonce and username from a client-first-message.
func parseClientFirst(msg string) (nonce, username string) {
	bare := strings.TrimPrefix(msg, "n,,")
	for _, part := range strings.Split(bare, ",") {
		if strings.HasPrefix(part, "r=") {
			nonce = part[2:]
		}
		if strings.HasPrefix(part, "n=") {
			username = part[2:]
		}
	}
	return
}

// parseClientFinal extracts the client-final-message-without-proof and proof bytes.
func parseClientFinal(msg string) (withoutProof string, proof []byte, err error) {
	idx := strings.LastIndex(msg, ",p=")
	if idx < 0 {
		return "", nil, fmt.Errorf("no proof in client-final-message: %q", msg)
	}
	withoutProof = msg[:idx]
	proof, err = base64.StdEncoding.DecodeString(msg[idx+3:])
	if err != nil {
		return "", nil, fmt.Errorf("decode proof: %w", err)
	}
	return withoutProof, proof, nil
}
