package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"github.com/toolkits/slice"
	"net"
	"regexp"
	"strings"
)

type GeneralStruct interface {
	// a general interface to structures.
	ToJson() (string, error) // This function is used when comparing structures read from yaml files to the resulting fields in the structure.
}

//-------------------rules-------------------------------------
type Sender struct {
	// if SenderName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	SenderName string                   `yaml:"senderName,omitempty" json:"senderName,omitempty" bson:"SenderName" structs:"SenderName,omitempty"`
	SenderType string                   `yaml:"senderType,omitempty" json:"senderType,omitempty" bson:"SenderType,omitempty" structs:"SenderType,omitempty"`
	SenderList []ExpandedSenderReceiver `yaml:"-" json:"senderList,omitempty" bson:"SenderList,omitempty" structs:"SenderList,omitempty"`
}

type Receiver struct {
	// if ReceiverName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	ReceiverName string                   `yaml:"receiverName,omitempty" json:"receiverName,omitempty" bson:"ReceiverName" structs:"ReceiverName,omitempty"`
	ReceiverType string                   `yaml:"receiverType,omitempty" json:"receiverType,omitempty" bson:"ReceiverType,omitempty" structs:"ReceiverType,omitempty"`
	ReceiverList []ExpandedSenderReceiver `yaml:"-" json:"receiverList,omitempty" bson:"ReceiverList,omitempty" structs:"ReceiverList,omitempty"`
}

// Resource structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Resource struct {
	/* Examples: // pay attention that the resource type should match the protocol
	path:<http_path_name>,
	kafkaTopic:<kafka_topic_name>
	consumerGroup:<consumer_group_name>
	port:<port number>
	*/
	ResourceType      string         `yaml:"resourceType,omitempty" json:"resourceType,omitempty" bson:"ResourceType,omitempty" structs:"ResourceType,omitempty"`
	ResourceName      string         `yaml:"resourceName,omitempty" json:"resourceName,omitempty" bson:"ResourceName,omitempty" structs:"ResourceName,omitempty"`
	ResourceNameRegex *regexp.Regexp `yaml:"-" json:"-,omitempty" bson:"ResourceNameRegex,omitempty" structs:"ResourceNameRegex,omitempty"`
}

// Condition structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Condition struct {
	Attribute        string         `yaml:"attribute,omitempty" json:"attribute" bson:"Attribute" structs:"Attribute,omitempty"`
	Method           string         `yaml:"method,omitempty" json:"method" bson:"Method" structs:"Method,omitempty"`
	Value            string         `yaml:"value,omitempty" json:"value" bson:"Value" structs:"Value,omitempty"`
	ValueInt         int64          `yaml:"-" json:"ValueInt,omitempty" bson:"ValueInt,omitempty" structs:"ValueInt,omitempty"`
	ValueFloat       float64        `yaml:"-" json:"ValueFloat,omitempty" bson:"ValueFloat,omitempty" structs:"ValueFloat,omitempty"`
	ValueRegex       *regexp.Regexp `yaml:"-" json:"ValueRegex,omitempty" bson:"ValueRegex,omitempty" structs:"ValueRegex,omitempty"`
	ValueStringRegex *regexp.Regexp `yaml:"-" json:"ValueStringRegex,omitempty" bson:"ValueStringRegex,omitempty" structs:"ValueStringRegex,omitempty"`

	AttributeIsSenderLabel    bool   `yaml:"-" json:"AttributeIsSenderLabel,omitempty" bson:"AttributeIsSenderLabel,omitempty" structs:"AttributeIsSenderLabel,omitempty"`
	AttributeSenderLabelKey   string `yaml:"-" json:"AttributeSenderLabelKey,omitempty" bson:"AttributeSenderLabelKey,omitempty" structs:"AttributeSenderLabelKey,omitempty"`
	AttributeIsReceiverLabel  bool   `yaml:"-" json:"AttributeIsReceiverLabel,omitempty" bson:"AttributeIsReceiverLabel,omitempty" structs:"AttributeIsReceiverLabel,omitempty"`
	AttributeReceiverLabelKey string `yaml:"-" json:"AttributeReceiverLabelKey,omitempty" bson:"AttributeReceiverLabelKey,omitempty" structs:"AttributeReceiverLabelKey,omitempty"`
	ValueIsReceiverLabel      bool   `yaml:"-" json:"ValueIsReceiverLabel,omitempty" bson:"ValueIsReceiverLabel,omitempty" structs:"ValueIsReceiverLabel,omitempty"`
	ValueReceiverLabelKey     string `yaml:"-" json:"ValueReceiverLabelKey,omitempty" bson:"ValueReceiverLabelKey,omitempty" structs:"ValueReceiverLabelKey,omitempty"`

	AttributeIsSenderObject          bool   `yaml:"-" json:"AttributeIsSenderObject,omitempty" bson:"AttributeIsSenderObject,omitempty" structs:"AttributeIsSenderObject,omitempty"`
	AttributeIsReceiverObject        bool   `yaml:"-" json:"AttributeIsReceiverObject,omitempty" bson:"AttributeIsReceiverObject,omitempty" structs:"AttributeIsReceiverObject,omitempty"`
	ValueIsReceiverObject            bool   `yaml:"-" json:"ValueIsReceiverObject,omitempty" bson:"ValueIsReceiverObject,omitempty" structs:"ValueIsReceiverObject,omitempty"`
	AttributeSenderObjectAttribute   string `yaml:"-" json:"AttributeSenderObjectAttribute,omitempty" bson:"AttributeSenderObjectAttribute,omitempty" structs:"AttributeSenderObjectAttribute,omitempty"`
	AttributeReceiverObjectAttribute string `yaml:"-" json:"AttributeReceiverObjectAttribute,omitempty" bson:"AttributeReceiverObjectAttribute,omitempty" structs:"AttributeReceiverObjectAttribute,omitempty"`
	ValueReceiverObject              string `yaml:"-" json:"ValueReceiverObject,omitempty" bson:"ValueReceiverObject,omitempty" structs:"ValueReceiverObject,omitempty"`

	AttributeIsJsonpath         bool   `yaml:"-" json:"AttributeIsJsonpath,omitempty" bson:"AttributeIsJsonpath,omitempty" structs:"AttributeIsJsonpath,omitempty"`
	AttributeIsJsonpathRelative bool   `yaml:"-" json:"AttributeIsJsonpathRelative,omitempty" bson:"AttributeIsJsonpathRelative,omitempty" structs:"AttributeIsJsonpathRelative,omitempty"`
	AttributeJsonpathQuery      string `yaml:"-" json:"AttributeJsonpathQuery,omitempty" bson:"AttributeJsonpathQuery,omitempty" structs:"AttributeJsonpathQuery,omitempty"`

	OriginalAttribute string `yaml:"-" json:"OriginalAttribute,omitempty" bson:"OriginalAttribute,omitempty" structs:"OriginalAttribute,omitempty"` // used in hash
	OriginalValue     string `yaml:"-" json:"OriginalValue,omitempty" bson:"OriginalValue,omitempty" structs:"OriginalValue,omitempty"`             // used in hash
}

type ConditionNode struct {
	Attribute string `yaml:"attribute,omitempty" json:"attribute" bson:"Attribute" structs:"Attribute,omitempty"`
	Method    string `yaml:"method,omitempty" json:"method" bson:"Method" structs:"Method,omitempty"`
	Value     string `yaml:"value,omitempty" json:"value" bson:"Value" structs:"Value,omitempty"`
}

func ConditionFromConditionNode(c ConditionNode) Condition {
	c_out := Condition{}

	c_out.Attribute = c.Attribute
	c_out.Method = c.Method
	c_out.Value = c.Value

	return c_out

}

func ReadCondition(v map[string]interface{}) (ConditionNode) {

	c := ConditionNode{}
	for k, val := range v {
		switch k {
		case "attribute", "Attribute":
			c.Attribute = val.(string)

		case "method", "Method":
			c.Method = val.(string)

		case "value", "Value":
			c.Value = fmt.Sprintf("%v", val) // to avoid interface interpreted as int which causes panic

		}
	}
	return c
}

func getKeys(v map[string]interface{}) ([]string) {
	keys := []string{}
	for key, _ := range (v) {
		keys = append(keys, key)
	}
	return keys
}

func isConditionNode(v map[string]interface{}) bool {
	keys := getKeys(v)
	flagAtt := slice.ContainsString(keys, "Attribute") || slice.ContainsString(keys, "attribute")
	flagMethod := slice.ContainsString(keys, "Method") || slice.ContainsString(keys, "method")
	flagValue := slice.ContainsString(keys, "Value") || slice.ContainsString(keys, "value")

	if len(keys) == 2 && flagAtt && flagMethod {
		return true
	}
	if len(keys) == 3 && flagAtt && flagMethod && flagValue {
		return true
	}
	return false
}

// ANDConditions structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type ANDConditions struct {
	ANDConditions []Condition `yaml:"ANDconditions,omitempty" json:"ANDConditions,omitempty" bson:"ANDConditions,omitempty"`
}

// Rule structure - as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Rule struct {
	// rule syntax:
	//	<sender, receiver, resource, operation> : <conditions> : <decision>
	//
	RuleID        string          `yaml:"rule_id,omitempty" json:"ruleID,omitempty" bson:"RuleID,omitempty" structs:"RuleID,omitempty"`
	Sender        Sender          `yaml:"sender,omitempty" json:"sender,omitempty" bson:"Sender" structs:"Sender,omitempty"`
	Receiver      Receiver        `yaml:"receiver,omitempty" json:"receiver,omitempty" bson:"Receiver" structs:"Receiver,omitempty"`
	Protocol      string          `yaml:"protocol,omitempty" json:"protocol,omitempty" bson:"ResourceProtocol" structs:"Protocol,omitempty"`
	Resource      Resource        `yaml:"resource,omitempty" json:"resource,omitempty" bson:"Resource" structs:"Resource,omitempty"`
	Operation     string          `yaml:"operation,omitempty" json:"operation,omitempty" bson:"Operation" structs:"Operation,omitempty"`
	DNFConditions []ANDConditions `yaml:"DNFconditions,omitempty" json:"dnfConditions,omitempty" bson:"DNFConditions,omitempty" structs:"DNFConditions,omitempty"`
	Decision      string          `yaml:"decision,omitempty" json:"decision,omitempty" bson:"Decision" structs:"Decision,omitempty"`

	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty" bson:"Metadata" structs:"Metadata,omitempty"`

	Hash string `yaml:"hash,omitempty" json:"hash,omitempty" bson:"Hash" structs:"Hash,omitempty"`

	OperationRegex                    *regexp.Regexp `yaml:"o,omitempty" json:"o,omitempty" bson:"OperationRegex,omitempty" structs:"OperationRegex,omitempty"`
	AlreadyConvertedFieldsToRegexFlag bool           `yaml:"-,omitempty" json:"-,omitempty" bson:"-,omitempty" structs:"-,omitempty"` // default is false
}

// Rules structure contains a list of rules
type Rules struct {
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

//
type ExpandedSenderReceiver struct {
	Name   string         `yaml:"-" json:"Name,omitempty" bson:"Name,omitempty"`
	Type   string         `yaml:"-" json:"Type,omitempty" bson:"Type,omitempty"`
	Regexp *regexp.Regexp `yaml:"-" json:"Regexp,omitempty" bson:"Regexp,omitempty"`
	IsIP   bool           `yaml:"-" json:"IsIP,omitempty" bson:"IsIP,omitempty"`
	IsCIDR bool           `yaml:"-" json:"IsCIDR,omitempty" bson:"IsCIDR,omitempty"`
	CIDR   net.IPNet      `yaml:"-" json:"CIDR,omitempty"  bson:"CIDR,omitempty"`
	IP     net.IP         `yaml:"-" json:"IP,omitempty" bson:"IP,omitempty"`
}

//-------------------------------------------
type RuleAndExtras struct {
	MaplRule                       Rule   `json:"maplRule" binding:"required,dive" bson:"MaplRule" structs:"maplRule"`
	Account                        string `json:"account" bson:"account" structs:"account"`
	Enabled                        *bool  `json:"enabled" bson:"enabled" structs:"enabled"`
	Origin                         string `json:"origin" bson:"origin" structs:"origin"`
	BasedOnActivityCoveredByRuleId string `json:"basedOnActivityCoveredByRuleId" bson:"basedOnActivityCoveredByRuleId" structs:"basedOnActivityCoveredByRuleId"`
}

type RulesAndExtras struct {
	Rules []RuleAndExtras `json:"rules" binding:"required,dive" bson:"RulesAndExtras" structs:"rules"`
}

type RulesAndExtrasAndDeprecated struct {
	Rules        []RuleAndExtras `json:"rules" binding:"required,dive" bson:"RulesAndExtras" structs:"rules"`
	UpdatedRules []RuleAndExtras `json:"suggested_simple_rule_update" binding:"required,dive" bson:"UpdatedRules" structs:"suggested_simple_rule_update"`
	Deprecated   []string        `json:"deprecated_rules" binding:"required,dive" bson:"Deprecated" structs:"deprecated_rules"`
	NotUsed      []string        `json:"not_used_non_deprecatable_rules" binding:"required,dive" bson:"NotUsed" structs:"not_used_non_deprecatable_rules"`
	Used         []string        `json:"used_rules" binding:"required,dive" bson:"Used" structs:"used_rules"`
}

type MAPLDb struct {
	//bongo.DocumentBase `bson:",inline"`
	Id            string `json:"id" `
	Created       string `json:"created"`
	RuleAndExtras `bson:",inline" bson:"RuleAndExtras"`
	MaplRuleHash  string `json:"-" bson:"MaplRuleHash"`
}

//-------------------------------------------

// ToJson converts a structure into a json string
func (rule Rule) ToJson() (string, error) { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// ToJson converts a structure into a json string
func (rule Rule) ToJsonNoIndent() (string, error) { // method of GeneralStruct interface
	jsonBytes, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// ToJson converts a structure into a json string
func (rules Rules) ToJson() (string, error) { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
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
	return fmt.Sprintf("<%v-%v-%v>", c.OriginalAttribute, c.Method, c.Value)
}

func (andConditions *ANDConditions) String() string {
	c_strings := []string{}
	for _, condition := range (andConditions.ANDConditions) {
		c_strings = append(c_strings, condition.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(c_strings, " && "))
}

type RuleStrings struct {
	RuleSetId        string
	SenderString     string
	ReceiverString   string
	ProtocolString   string
	ResourceString   string
	OperationString  string
	ConditionsString string
	DecisionString   string
}

func GetRuleStrings(r *Rule) RuleStrings {
	output := RuleStrings{}

	output.SenderString = r.Sender.String()
	output.ReceiverString = r.Receiver.String()

	output.ProtocolString = "default"
	if r.Protocol != "" {
		output.ProtocolString = r.Protocol
	}

	output.ResourceString = r.Resource.String()

	output.OperationString = "default"
	if r.Operation != "" {
		output.OperationString = r.Operation
	}

	output.DecisionString = "default"
	if r.Decision != "" {
		output.DecisionString = r.Decision
	}

	conditionsStrings := []string{}
	for _, andConditions := range (r.DNFConditions) {
		conditionsStrings = append(conditionsStrings, andConditions.String())
	}
	output.ConditionsString = strings.Join(conditionsStrings, " OR ")

	return output
}
