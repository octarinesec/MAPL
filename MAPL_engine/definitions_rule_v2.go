package MAPL_engine

import (
	"regexp"
)

type RuleV2 struct {
	// rule syntax:
	//	<sender, receiver, resource, operation> : <conditions> : <decision>
	//
	RuleID     string      `yaml:"rule_id,omitempty" json:"ruleID,omitempty" bson:"RuleID,omitempty" structs:"RuleID,omitempty"`
	Sender     Sender      `yaml:"sender,omitempty" json:"sender,omitempty" bson:"Sender" structs:"Sender,omitempty"`
	Receiver   Receiver    `yaml:"receiver,omitempty" json:"receiver,omitempty" bson:"Receiver" structs:"Receiver,omitempty"`
	Protocol   string      `yaml:"protocol,omitempty" json:"protocol,omitempty" bson:"ResourceProtocol" structs:"Protocol,omitempty"`
	Resource   Resource    `yaml:"resource,omitempty" json:"resource,omitempty" bson:"Resource" structs:"Resource,omitempty"`
	Operation  string      `yaml:"operation,omitempty" json:"operation,omitempty" bson:"Operation" structs:"Operation,omitempty"`

	//Conditions interface{} `yaml:"conditions,omitempty" json:"conditions,omitempty" bson:"conditions,omitempty" structs:"conditions,omitempty"`
	//ConditionsTree Node `yaml:"conditionsTree,omitempty" json:"conditionsTree,omitempty" bson:"conditionsTree,omitempty" structs:"conditionsTree,omitempty"`

	Conditions ConditionsTree `yaml:"conditions,omitempty" json:"conditions,omitempty" bson:"conditions,omitempty" structs:"conditions,omitempty"`

	Decision string `yaml:"decision,omitempty" json:"decision,omitempty" bson:"Decision" structs:"Decision,omitempty"`

	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty" bson:"Metadata" structs:"Metadata,omitempty"`

	Hash string `yaml:"hash,omitempty" json:"hash,omitempty" bson:"Hash" structs:"Hash,omitempty"`

	OperationRegex                    *regexp.Regexp `yaml:"o,omitempty" json:"o,omitempty" bson:"OperationRegex,omitempty" structs:"OperationRegex,omitempty"`
	AlreadyConvertedFieldsToRegexFlag bool           `yaml:"-,omitempty" json:"-,omitempty" bson:"-,omitempty" structs:"-,omitempty"` // default is false
}

// Rules structure contains a list of rules
type RulesV2 struct {
	Rules []RuleV2 `yaml:"rules,omitempty" json:"rules,omitempty"`
}
