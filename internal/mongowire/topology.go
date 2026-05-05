package mongowire

import (
	"encoding/binary"
	"net"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// topologyFields are the BSON fields in hello/isMaster responses that contain
// replica set member addresses. These must be rewritten so the client always
// connects through the proxy, never directly to backend members.
var topologyFields = []string{"hosts", "passives", "arbiters"}

// RewriteTopology inspects an OP_MSG response body and, if it looks like a
// hello/isMaster response with replica set topology info, replaces all member
// addresses with proxyAddr. Returns the (possibly modified) body.
//
// The detection is lightweight: if the document contains a "hosts" field,
// it's treated as a topology response. Non-topology responses pass through
// unchanged with minimal overhead (one BSON key lookup).
//
// Handles FlagChecksumPresent: if the checksum flag is set, the trailing
// 4-byte CRC32 is stripped and the flag is cleared, since the checksum
// would be invalidated by rewriting.
func RewriteTopology(body []byte, proxyAddr string) []byte {
	return RewriteTopologyWithMap(body, proxyAddr, nil)
}

// RewriteTopologyWithMap is like RewriteTopology, but it maps each backend
// member address to a specific proxy address when topologyMap contains one.
// Addresses missing from topologyMap fall back to proxyAddr.
func RewriteTopologyWithMap(body []byte, proxyAddr string, topologyMap map[string]string) []byte {
	if len(body) < 5 {
		return body
	}

	// Parse OP_MSG: 4 bytes flags + section(s) [+ optional 4-byte checksum].
	flags := binary.LittleEndian.Uint32(body[0:4])

	// Determine the section data, excluding any trailing checksum.
	sectionData := body[4:]
	hasChecksum := flags&FlagChecksumPresent != 0
	if hasChecksum {
		if len(sectionData) < 4 {
			return body
		}
		// Last 4 bytes are the CRC32 checksum; exclude from section parsing.
		sectionData = sectionData[:len(sectionData)-4]
	}

	if len(sectionData) == 0 || sectionData[0] != SectionBody {
		return body
	}
	rem := sectionData[1:] // skip section kind byte

	if len(rem) < 4 {
		return body
	}
	docLen := int(binary.LittleEndian.Uint32(rem[0:4]))
	if docLen < 5 || docLen > len(rem) {
		return body
	}
	doc := bson.Raw(rem[:docLen])

	// Quick check: does this response contain topology info?
	if _, err := doc.LookupErr("hosts"); err != nil {
		return body // not a topology response
	}

	// Rewrite the document.
	rewritten, err := rewriteTopologyDoc(doc, proxyAddr, topologyMap)
	if err != nil {
		return body // on error, pass through unchanged
	}

	// Rebuild the OP_MSG body.
	// Clear the checksum flag since the rewrite invalidates any checksum.
	newFlags := flags &^ FlagChecksumPresent
	trailingSections := rem[docLen:]

	result := make([]byte, 4+1+len(rewritten)+len(trailingSections))
	binary.LittleEndian.PutUint32(result[0:4], newFlags)
	result[4] = SectionBody
	copy(result[5:], rewritten)
	copy(result[5+len(rewritten):], trailingSections)

	return result
}

// rewriteTopologyDoc rewrites topology fields in a hello/isMaster BSON document.
func rewriteTopologyDoc(doc bson.Raw, proxyAddr string, topologyMap map[string]string) ([]byte, error) {
	// Decode into ordered D so we preserve field order.
	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		return nil, err
	}

	for i := range d {
		key := strings.ToLower(d[i].Key)

		// Rewrite array fields: hosts, passives, arbiters.
		for _, tf := range topologyFields {
			if key == tf {
				if arr, ok := d[i].Value.(bson.A); ok {
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

		// Rewrite "me" field.
		if key == "me" {
			if s, ok := d[i].Value.(string); ok {
				d[i].Value = rewriteTopologyAddr(s, proxyAddr, topologyMap)
			}
		}

		// Rewrite "primary" field.
		if key == "primary" {
			if s, ok := d[i].Value.(string); ok {
				d[i].Value = rewriteTopologyAddr(s, proxyAddr, topologyMap)
			}
		}
	}

	return bson.Marshal(d)
}

func rewriteTopologyAddr(addr, proxyAddr string, topologyMap map[string]string) string {
	if mapped := lookupTopologyMap(addr, topologyMap); mapped != "" {
		return mapped
	}
	if proxyAddr != "" {
		return proxyAddr
	}
	return addr
}

func lookupTopologyMap(addr string, topologyMap map[string]string) string {
	if len(topologyMap) == 0 {
		return ""
	}
	if mapped := topologyMap[addr]; mapped != "" {
		return mapped
	}
	if mapped := topologyMap[strings.ToLower(addr)]; mapped != "" {
		return mapped
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if mapped := topologyMap[net.JoinHostPort(strings.ToLower(host), port)]; mapped != "" {
		return mapped
	}
	return topologyMap[strings.ToLower(host)+":"+port]
}
