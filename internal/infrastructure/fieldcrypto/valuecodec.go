package fieldcrypto

import (
	"encoding/json"
)

const (
	typeStr  = "str"
	typeNum  = "num"
	typeBool = "bool"
	typeNull = "null"
)

type taggedValue struct {
	T string `json:"t"`
	V any    `json:"v"`
}

// EncodeValue serializes a scalar to type-tagged JSON bytes.
func EncodeValue(value any) ([]byte, error) {
	var tagged taggedValue
	switch v := value.(type) {
	case nil:
		tagged = taggedValue{T: typeNull, V: nil}
	case bool:
		tagged = taggedValue{T: typeBool, V: v}
	case float64:
		tagged = taggedValue{T: typeNum, V: v}
	case int:
		tagged = taggedValue{T: typeNum, V: float64(v)}
	case int64:
		tagged = taggedValue{T: typeNum, V: float64(v)}
	case string:
		tagged = taggedValue{T: typeStr, V: v}
	default:
		return nil, NewUnsupportedType()
	}
	return json.Marshal(tagged)
}

// DecodeValue restores a scalar from type-tagged JSON bytes.
func DecodeValue(raw []byte) (any, error) {
	var tagged taggedValue
	if err := json.Unmarshal(raw, &tagged); err != nil {
		return nil, NewUnsupportedType()
	}
	switch tagged.T {
	case typeNull:
		if tagged.V != nil {
			return nil, NewUnsupportedType()
		}
		return nil, nil
	case typeBool:
		v, ok := tagged.V.(bool)
		if !ok {
			return nil, NewUnsupportedType()
		}
		return v, nil
	case typeNum:
		switch v := tagged.V.(type) {
		case float64:
			return v, nil
		case json.Number:
			f, err := v.Float64()
			if err != nil {
				return nil, NewUnsupportedType()
			}
			return f, nil
		default:
			return nil, NewUnsupportedType()
		}
	case typeStr:
		v, ok := tagged.V.(string)
		if !ok {
			return nil, NewUnsupportedType()
		}
		return v, nil
	default:
		return nil, NewUnsupportedType()
	}
}
