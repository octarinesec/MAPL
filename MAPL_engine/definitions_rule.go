package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"github.com/toolkits/slice"
	"github.com/yalp/jsonpath"
	dc "gopkg.in/getlantern/deepcopy.v1"
	"net"
	"regexp"
	"strings"
)

// -------------------rules-------------------------------------
type Sender struct {
	// if SenderName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	SenderName string                   `yaml:"senderName,omitempty" json:"senderName,omitempty" bson:"senderName" structs:"senderName,omitempty"`
	SenderType string                   `yaml:"senderType,omitempty" json:"senderType,omitempty" bson:"senderType,omitempty" structs:"senderType,omitempty"`
	SenderList []ExpandedSenderReceiver `yaml:"-,omitempty" json:"-,omitempty" bson:"senderList,omitempty" structs:"senderList,omitempty"`
}

type Receiver struct {
	// if ReceiverName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	ReceiverName string                   `yaml:"receiverName,omitempty" json:"receiverName,omitempty" bson:"receiverName" structs:"receiverName,omitempty"`
	ReceiverType string                   `yaml:"receiverType,omitempty" json:"receiverType,omitempty" bson:"receiverType,omitempty" structs:"receiverType,omitempty"`
	ReceiverList []ExpandedSenderReceiver `yaml:"-,omitempty" json:"-,omitempty" bson:"receiverList,omitempty" structs:"receiverList,omitempty"`
}

type ExpandedSenderReceiver struct {
	Name   string         `yaml:"-" json:"name,omitempty" bson:"name,omitempty"`
	Type   string         `yaml:"-" json:"type,omitempty" bson:"type,omitempty"`
	Regexp *regexp.Regexp `yaml:"-" json:"regexp,omitempty" bson:"regexp,omitempty"`
	IsIP   bool           `yaml:"-" json:"isIP,omitempty" bson:"isIP,omitempty"`
	IsCIDR bool           `yaml:"-" json:"isCIDR,omitempty" bson:"isCIDR,omitempty"`
	CIDR   net.IPNet      `yaml:"-" json:"CIDR,omitempty"  bson:"CIDR,omitempty"`
	IP     net.IP         `yaml:"-" json:"IP,omitempty" bson:"IP,omitempty"`
}

// Resource structure - part of the rule as defined in MAPL (docs/MAPL_SPEC.md)
type Resource struct {
	/* Examples: // pay attention that the resource type should match the protocol
	path:<http_path_name>,
	kafkaTopic:<kafka_topic_name>
	consumerGroup:<consumer_group_name>
	port:<port number>
	*/
	ResourceType      string         `yaml:"resourceType,omitempty" json:"resourceType,omitempty" bson:"resourceType,omitempty" structs:"resourceType,omitempty"`
	ResourceName      string         `yaml:"resourceName,omitempty" json:"resourceName,omitempty" bson:"resourceName,omitempty" structs:"resourceName,omitempty"`
	ResourceNameRegex *regexp.Regexp `yaml:"-" json:"-,omitempty" bson:"resourceNameRegex,omitempty" structs:"resourceNameRegex,omitempty"`
}

// Condition structure - part of the rule as defined in MAPL (docs/MAPL_SPEC.md)
type Condition struct {
	// TO-DO: convert to AttributeStruct and ValueStruct?
	Attribute        string         `yaml:"attribute,omitempty" json:"attribute" bson:"attribute" structs:"attribute,omitempty"`
	Method           string         `yaml:"method,omitempty" json:"method" bson:"method" structs:"method,omitempty"`
	Value            string         `yaml:"value,omitempty" json:"value" bson:"value" structs:"value,omitempty"`
	ValueInt         *int64         `yaml:"-" json:"-,omitempty" bson:"valueInt,omitempty" structs:"valueInt,omitempty"`
	ValueFloat       *float64       `yaml:"-" json:"-,omitempty" bson:"valueFloat,omitempty" structs:"valueFloat,omitempty"`
	ValueRegex       *regexp.Regexp `yaml:"-" json:"-,omitempty" bson:"valueRegex,omitempty" structs:"valueRegex,omitempty"`
	ValueStringRegex *regexp.Regexp `yaml:"-" json:"-,omitempty" bson:"valueStringRegex,omitempty" structs:"valueStringRegex,omitempty"`

	AttributeIsSenderLabel    bool   `yaml:"-" json:"-,omitempty" bson:"attributeIsSenderLabel,omitempty" structs:"attributeIsSenderLabel,omitempty"`
	AttributeSenderLabelKey   string `yaml:"-" json:"-,omitempty" bson:"attributeSenderLabelKey,omitempty" structs:"attributeSenderLabelKey,omitempty"`
	AttributeIsReceiverLabel  bool   `yaml:"-" json:"-,omitempty" bson:"attributeIsReceiverLabel,omitempty" structs:"attributeIsReceiverLabel,omitempty"`
	AttributeReceiverLabelKey string `yaml:"-" json:"-,omitempty" bson:"attributeReceiverLabelKey,omitempty" structs:"attributeReceiverLabelKey,omitempty"`
	ValueIsReceiverLabel      bool   `yaml:"-" json:"-,omitempty" bson:"valueIsReceiverLabel,omitempty" structs:"valueIsReceiverLabel,omitempty"`
	ValueReceiverLabelKey     string `yaml:"-" json:"-,omitempty" bson:"valueReceiverLabelKey,omitempty" structs:"valueReceiverLabelKey,omitempty"`

	AttributeIsSenderObject          bool   `yaml:"-" json:"-,omitempty" bson:"attributeIsSenderObject,omitempty" structs:"attributeIsSenderObject,omitempty"`
	AttributeIsReceiverObject        bool   `yaml:"-" json:"-,omitempty" bson:"attributeIsReceiverObject,omitempty" structs:"attributeIsReceiverObject,omitempty"`
	ValueIsReceiverObject            bool   `yaml:"-" json:"-,omitempty" bson:"valueIsReceiverObject,omitempty" structs:"valueIsReceiverObject,omitempty"`
	AttributeSenderObjectAttribute   string `yaml:"-" json:"-,omitempty" bson:"attributeSenderObjectAttribute,omitempty" structs:"attributeSenderObjectAttribute,omitempty"`
	AttributeReceiverObjectAttribute string `yaml:"-" json:"-,omitempty" bson:"attributeReceiverObjectAttribute,omitempty" structs:"attributeReceiverObjectAttribute,omitempty"`
	ValueReceiverObject              string `yaml:"-" json:"-,omitempty" bson:"valueReceiverObject,omitempty" structs:"valueReceiverObject,omitempty"`

	AttributeIsJsonpath         bool                `yaml:"-" json:"-,omitempty" bson:"attributeIsJsonpath,omitempty" structs:"attributeIsJsonpath,omitempty"`
	AttributeIsJsonpathRelative bool                `yaml:"-" json:"-,omitempty" bson:"attributeIsJsonpathRelative,omitempty" structs:"attributeIsJsonpathRelative,omitempty"`
	AttributeJsonpathQuery      string              `yaml:"-" json:"-,omitempty" bson:"attributeJsonpathQuery,omitempty" structs:"attributeJsonpathQuery,omitempty"`
	PreparedJsonpathQuery       jsonpath.FilterFunc `yaml:"-" json:"-,omitempty"`

	ReturnValueJsonpath                          map[string]string              `yaml:"-" json:"returnValueJsonpath,omitempty" bson:"returnValueJsonpath,omitempty"`
	ReturnValueJsonpathOriginal                  map[string]string              `yaml:"-" json:"returnValueJsonpathOriginal,omitempty" bson:"returnValueJsonpath,omitempty"`
	PreparedReturnValueJsonpathQuery             map[string]jsonpath.FilterFunc `yaml:"-" json:"-,omitempty"`
	PreparedReturnValueJsonpathQueryRelativeFlag map[string]bool                `yaml:"-" json:"-,omitempty"`

	OriginalAttribute string `yaml:"-" json:"-,omitempty" bson:"originalAttribute,omitempty" structs:"originalAttribute,omitempty"` // used in hash
	OriginalMethod    string `yaml:"-" json:"-,omitempty" bson:"originalMethod,omitempty" structs:"originalMethod,omitempty"`       // used in hash
	OriginalValue     string `yaml:"-" json:"-,omitempty" bson:"originalValue,omitempty" structs:"originalValue,omitempty"`         // used in hash
}

type Rule struct {
	// rule syntax:
	//	<sender, receiver, resource, operation> : <conditions> : <decision>
	//
	RuleID    string   `yaml:"ruleID,omitempty" json:"ruleID,omitempty" bson:"ruleID,omitempty" structs:"ruleID,omitempty"`
	Sender    Sender   `yaml:"sender,omitempty" json:"sender,omitempty" bson:"sender" structs:"Sender,omitempty"`
	Receiver  Receiver `yaml:"receiver,omitempty" json:"receiver,omitempty" bson:"receiver" structs:"Receiver,omitempty"`
	Protocol  string   `yaml:"protocol,omitempty" json:"protocol,omitempty" bson:"protocol" structs:"protocol,omitempty"`
	Resource  Resource `yaml:"resource,omitempty" json:"resource,omitempty" bson:"resource" structs:"resource,omitempty"`
	Operation string   `yaml:"operation,omitempty" json:"operation,omitempty" bson:"operation" structs:"operation,omitempty"`

	Conditions ConditionsTree `yaml:"conditions,omitempty" json:"conditions,omitempty" bson:"conditions,omitempty" structs:"conditions,omitempty"`

	Decision string `yaml:"decision,omitempty" json:"decision,omitempty" bson:"decision" structs:"decision,omitempty"`

	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty" bson:"metadata" structs:"metadata,omitempty"`

	Hash string `yaml:"hash,omitempty" json:"hash,omitempty" bson:"hash" structs:"hash,omitempty"`

	OperationRegex                    *regexp.Regexp `yaml:"operationRegex,omitempty" json:"operationRegex,omitempty" bson:"operationRegex,omitempty" structs:"operationRegex,omitempty"`
	AlreadyConvertedFieldsToRegexFlag bool           `yaml:"-,omitempty" json:"-,omitempty" bson:"-,omitempty" structs:"-,omitempty"` // default is false

	predefinedStringsAndLists PredefinedStringsAndLists
	ruleAlreadyPrepared       bool
	preparedRule              *Rule
}

// Rules structure contains a list of rules
type Rules struct {
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type ConditionNode struct {
	Attribute                   string            `yaml:"attribute,omitempty" json:"attribute" bson:"attribute" structs:"attribute,omitempty"`
	Method                      string            `yaml:"method,omitempty" json:"method" bson:"method" structs:"method,omitempty"`
	Value                       string            `yaml:"value,omitempty" json:"value" bson:"value" structs:"value,omitempty"`
	ReturnValueJsonpathOriginal map[string]string `yaml:"returnValueJsonpathOriginal,omitempty" json:"returnValueJsonpathOriginal" bson:"returnValueJsonpathOriginal" structs:"returnValueJsonpathOriginal,omitempty"`
	ReturnValueJsonpath         map[string]string `yaml:"returnValueJsonpath,omitempty" json:"returnValueJsonpath" bson:"returnValueJsonpath" structs:"returnValueJsonpath,omitempty"`
}

func ConditionFromConditionNode(c ConditionNode) Condition {
	c_out := Condition{}

	c_out.Attribute = c.Attribute
	c_out.Method = c.Method
	c_out.Value = c.Value
	c_out.ReturnValueJsonpath = c.ReturnValueJsonpath

	c_out.PreparedReturnValueJsonpathQuery = make(map[string]jsonpath.FilterFunc)
	c_out.PreparedReturnValueJsonpathQueryRelativeFlag = make(map[string]bool)

	dc.Copy(&c_out.ReturnValueJsonpathOriginal, &c.ReturnValueJsonpath)
	dc.Copy(&c_out.ReturnValueJsonpath, &c.ReturnValueJsonpath)
	for k, v := range c_out.ReturnValueJsonpath {
		relativeFlag := false
		if strings.HasPrefix(c.ReturnValueJsonpath[k], "jsonpath:$RELATIVE") {
			relativeFlag = true
		}
		c_out.ReturnValueJsonpath[k] = strings.Replace(v, "jsonpath:$RELATIVE", "$", 1)
		c_out.ReturnValueJsonpath[k] = strings.Replace(v, "jsonpath:$", "$", 1)

		tempAtt := c_out.ReturnValueJsonpath[k]
		p, err := jsonpath.Prepare(tempAtt)
		if err != nil {
			c_out.PreparedReturnValueJsonpathQuery[k] = nil
		} else {
			c_out.PreparedReturnValueJsonpathQuery[k] = p
		}
		c_out.PreparedReturnValueJsonpathQueryRelativeFlag[k] = relativeFlag
	}

	return c_out

}

func ReadCondition(v map[string]interface{}) ConditionNode {

	c := ConditionNode{}
	for k, val := range v {
		switch k {
		case "attribute", "Attribute":
			c.Attribute = val.(string)

		case "method", "Method":
			c.Method = val.(string)

		case "value", "Value":
			c.Value = fmt.Sprintf("%v", val) // to avoid interface interpreted as int which causes panic

		case "returnValueJsonpath", "ReturnValueJsonpath":
			c.ReturnValueJsonpath = make(map[string]string)
			switch val.(type) {
			case map[string]interface{}:
				val2 := val.(map[string]interface{})
				for kk, vv := range val2 {
					c.ReturnValueJsonpath[kk] = vv.(string)
				}
			case map[interface{}]interface{}:
				val2 := val.(map[interface{}]interface{})
				for kk, vv := range val2 {
					c.ReturnValueJsonpath[kk.(string)] = vv.(string)
				}
			}
		}
	}
	return c
}

func getKeys(v map[string]interface{}) []string {
	keys := []string{}
	for key, _ := range v {
		keys = append(keys, key)
	}
	return keys
}

func isConditionNode(v map[string]interface{}) bool {
	keys := getKeys(v)
	flagAtt := slice.ContainsString(keys, "Attribute") || slice.ContainsString(keys, "attribute")
	flagMethod := slice.ContainsString(keys, "Method") || slice.ContainsString(keys, "method")
	flagValue := slice.ContainsString(keys, "Value") || slice.ContainsString(keys, "value")
	flagValue2 := slice.ContainsString(keys, "ValueInt") || slice.ContainsString(keys, "valueInt")
	flagValue3 := slice.ContainsString(keys, "ValueFloat") || slice.ContainsString(keys, "valueFloat")
	flagReturnValue := slice.ContainsString(keys, "ReturnValueJsonpath") || slice.ContainsString(keys, "returnValueJsonpath")

	extra := 0
	if flagReturnValue {
		extra += 1
	}

	if len(keys) == 2+extra && flagAtt && flagMethod {
		return true
	}
	if len(keys) == 3+extra && flagAtt && flagMethod && flagValue {
		return true
	}
	if len(keys) == 4+extra && flagAtt && flagMethod && flagValue && flagValue2 {
		return true
	}
	if len(keys) == 4+extra && flagAtt && flagMethod && flagValue && flagValue3 {
		return true
	}
	if len(keys) == 5+extra && flagAtt && flagMethod && flagValue && flagValue2 && flagValue3 {
		return true
	}

	return false
}

func (s *Sender) String() string {
	senderString := fmt.Sprintf("%v:%v", "{default type}:", s.SenderName)
	if s.SenderType != "" {
		senderString = fmt.Sprintf("%v:%v", s.SenderType, s.SenderName)
	}
	return senderString
}

func (r *Receiver) String() string {
	receiverString := fmt.Sprintf("%v:%v", "{default type}:", r.ReceiverName)
	if r.ReceiverType != "" {
		receiverString = fmt.Sprintf("%v:%v", r.ReceiverType, r.ReceiverName)
	}
	return receiverString
}

func (r *Resource) String() string {
	resourceString := "default:default"
	if r.ResourceType != "" {
		resourceString = fmt.Sprintf("%v:%v", r.ResourceType, r.ResourceName)
	}
	return resourceString
}

func (c *Condition) String() string {
	// return fmt.Sprintf("(%v %v %v)", c.Attribute, c.Method, c.Value)

	stringAttribute := c.Attribute
	if len(c.OriginalAttribute) > 0 {
		stringAttribute = c.OriginalAttribute
	}
	stringMethod := c.Method
	if len(c.OriginalMethod) > 0 {
		stringMethod = c.OriginalMethod
	}

	stringValue := c.Value
	if len(c.OriginalValue) > 0 {
		stringValue = c.OriginalValue
	}
	return fmt.Sprintf("<%v-%v-%v>", stringAttribute, stringMethod, stringValue)
}

func (c *Condition) MarshalJSON() ([]byte, error) {

	attributeString := c.Attribute
	if len(c.OriginalAttribute) > 0 {
		attributeString = c.OriginalAttribute
	}
	attributeString = strings.Replace(attributeString, "\\", "\\\\", -1)
	attributeString = strings.Replace(attributeString, "\"", "\\\"", -1)

	methodString := c.Method
	if len(c.OriginalMethod) > 0 {
		methodString = c.OriginalMethod
	}

	valueString := c.Value
	if len(c.OriginalValue) > 0 {
		valueString = c.OriginalValue
	}
	valueString = strings.Replace(valueString, "\\", "\\\\", -1)
	valueString = strings.Replace(valueString, "\"", "\\\"", -1)

	returnValueJsonpath := c.ReturnValueJsonpath
	if len(c.ReturnValueJsonpathOriginal) > 0 {
		returnValueJsonpath = c.ReturnValueJsonpathOriginal
	}

	str := fmt.Sprintf(`{"condition":{"attribute":"%v","method":"%v","value":"%v"}}`, attributeString, methodString, valueString)

	if returnValueJsonpath != nil {
		returnValueJsonpathJson, _ := json.Marshal(returnValueJsonpath)
		str = fmt.Sprintf(`{"condition":{"attribute":"%v","method":"%v","value":"%v","returnValueJsonpath":%v}}`, attributeString, methodString, valueString, string(returnValueJsonpathJson))
	}
	return []byte(str), nil
}
