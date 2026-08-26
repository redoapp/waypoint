package querylog

import (
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// maxShapeDepth stops a pathologically nested command document from causing
// unbounded recursion while shaping.
const maxShapeDepth = 12

// commandShape renders a Mongo command document with its values replaced by
// type placeholders, keeping keys, the command name, and the collection name.
//
// It is the Mongo counterpart to eliding SQL constants: the result describes
// what the client asked for without carrying the values it asked about, so it
// is safe at LevelNormalized and stable enough to fingerprint.
func commandShape(doc bson.Raw) string {
	var b strings.Builder
	shapeDoc(&b, doc, 0, true)
	return b.String()
}

func shapeDoc(b *strings.Builder, doc bson.Raw, depth int, isCommandRoot bool) {
	elems, err := doc.Elements()
	if err != nil {
		b.WriteString("{?}")
		return
	}
	if depth > maxShapeDepth {
		b.WriteString("{...}")
		return
	}

	b.WriteByte('{')
	for i, el := range elems {
		if i > 0 {
			b.WriteString(", ")
		}
		key := el.Key()
		b.WriteString(key)
		b.WriteString(": ")

		// The first key of a command document is the command name and its
		// value is the collection — both are structure, not data, so they
		// are kept verbatim.
		if isCommandRoot && i == 0 {
			if s, ok := el.Value().StringValueOK(); ok {
				b.WriteByte('"')
				b.WriteString(s)
				b.WriteByte('"')
				continue
			}
		}
		// $db names the database, which is already a logged field.
		if isCommandRoot && key == "$db" {
			if s, ok := el.Value().StringValueOK(); ok {
				b.WriteByte('"')
				b.WriteString(s)
				b.WriteByte('"')
				continue
			}
		}

		shapeValue(b, el.Value(), depth+1)
	}
	b.WriteByte('}')
}

func shapeValue(b *strings.Builder, v bson.RawValue, depth int) {
	if depth > maxShapeDepth {
		b.WriteString("?")
		return
	}

	switch v.Type {
	case bson.TypeEmbeddedDocument:
		sub, ok := v.DocumentOK()
		if !ok {
			b.WriteString("?object")
			return
		}
		shapeDoc(b, sub, depth, false)

	case bson.TypeArray:
		arr, ok := v.ArrayOK()
		if !ok {
			b.WriteString("?array")
			return
		}
		vals, err := arr.Values()
		if err != nil {
			b.WriteString("?array")
			return
		}
		b.WriteByte('[')
		// One representative element is enough to convey the shape; the
		// length is data, not structure.
		if len(vals) > 0 {
			shapeValue(b, vals[0], depth+1)
			if len(vals) > 1 {
				b.WriteString(", ...")
			}
		}
		b.WriteByte(']')

	default:
		b.WriteString(placeholderFor(v.Type))
	}
}

func placeholderFor(t bson.Type) string {
	switch t {
	case bson.TypeString:
		return "?string"
	case bson.TypeInt32:
		return "?int"
	case bson.TypeInt64:
		return "?long"
	case bson.TypeDouble:
		return "?double"
	case bson.TypeBoolean:
		return "?bool"
	case bson.TypeObjectID:
		return "?objectId"
	case bson.TypeDateTime:
		return "?date"
	case bson.TypeNull:
		return "?null"
	case bson.TypeBinary:
		return "?binary"
	case bson.TypeRegex:
		return "?regex"
	case bson.TypeDecimal128:
		return "?decimal"
	case bson.TypeTimestamp:
		return "?timestamp"
	default:
		return "?"
	}
}

// commandCollection returns the collection a command targets: the value of the
// command document's first key, when it is a string.
func commandCollection(doc bson.Raw) string {
	elems, err := doc.Elements()
	if err != nil || len(elems) == 0 {
		return ""
	}
	s, ok := elems[0].Value().StringValueOK()
	if !ok {
		return ""
	}
	return s
}
