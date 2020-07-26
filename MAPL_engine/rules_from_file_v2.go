package MAPL_engine

import (
	"errors"
	"fmt"
	"github.com/toolkits/slice"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// YamlReadRulesFromString function reads rules from a yaml string
func YamlReadRulesFromStringV2(yamlString string) (RulesV2, error) {

	var rules RulesV2
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return RulesV2{}, err
	}

	for i_rule, _ := range (rules.Rules) {
		err := ParseAndValidateConditions(&rules.Rules[i_rule])
		if err != nil {
			return RulesV2{}, err
		}
	}

	err = PrepareRulesV2(&rules)
	if err != nil {
		return RulesV2{}, err
	}

	return rules, nil
}

func YamlReadRulesFromFileV2(filename string) (RulesV2, error) {

	filename = strings.Replace(filename, "\\", "/", -1)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return RulesV2{}, err
	}

	err = testYaml(data)
	if err != nil {
		return RulesV2{}, err
	}

	rules, err := YamlReadRulesFromStringV2(string(data))
	return rules, err
}

func testYaml(data []byte) error {
	var z interface{}
	return yaml.UnmarshalStrict(data, &z)
}

func ParseAndValidateConditions(rule *RuleV2) error {

	if rule.Conditions == nil {
		return nil
	}
	c := rule.Conditions

	conditionsTree, err := ParseConditionsTree(c)
	if err != nil {
		return err
	}

	rule.ConditionsTree = conditionsTree

	return nil
}

func ParseConditionsTree(c interface{}) (Node, error) {

	conditionsTree, err := InterpretNode(c, "")
	if err != nil {
		return nil, err
	}

	return conditionsTree, nil
}

func InterpretNode(node interface{}, parentString string) (Node, error) {
	switch v := node.(type) {

	case map[interface{}]interface{}:
		return handleMapInterfaceInterface(v, node, parentString)

	case []interface{}: // array of nodes
		return handleInterfaceArray(node, parentString)

	default:
		return nil, fmt.Errorf("can't parse conditions %+v", v)
	}
	return nil, errors.New("can't parse conditions")
}

func handleMapInterfaceInterface(v map[interface{}]interface{}, node interface{}, parentString string) (Node, error) {

	// test if this is a condition:
	cond0, ok := node.(ConditionNode)
	fmt.Println(ok)
	fmt.Println(cond0)
	cond, ok := ReadCondition(v)
	if ok {
		c, err := prepareOneConditionNode(cond)
		if err != nil {
			return nil, err
		}
		if parentString != "" && parentString != "condition" {
			nodes, err := getNodeByParentString(parentString)
			if err != nil {
				return nil, err
			}
			nodes.Append(c)
			return nodes, nil
		} else {
			return c, nil
		}
	}
	// else it is supposed to be an AND, OR (etc) node:
	v2 := node.(map[interface{}]interface{})

	switch parentString {
	case "ANY":
		if len(v2) != 2 {
			return nil, fmt.Errorf("map of size differnet than 2 [ANY node]")
		}
		anyNode := &Any{}
		for key, val := range (v2) {
			if key.(string) == "parentAttribute" {
				anyNode.parentJsonAttribute = val.(string)
			} else {
				node, err := InterpretNode(val, key.(string)) // recursion!
				if err != nil {
					return nil, err
				}
				anyNode.Append(node)
			}
		}
		return anyNode, nil
	default:
		val, nodeType, err := getNodeValType(v2, parentString)
		if err != nil {
			return nil, err
		}
		node, err := InterpretNode(val, nodeType) // recursion!
		if err != nil {
			return nil, err
		}
		return node, nil

	}

	return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
}

func getNodeValType(node map[interface{}]interface{}, parentString string) (interface{}, string, error) {
	if len(node) != 1 {
		return nil, "", fmt.Errorf("map of size larger than 1 [%v node]", parentString)
	}

	for key, val := range (node) {
		return val, key.(string), nil
	}
	return nil, "", fmt.Errorf("not supposed to get here")
}

func prepareOneConditionNode(cond ConditionNode) (Node, error) {
	c := ConditionFromConditionNode(cond)
	valid, err := ValidateOneCondition(&c)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("error in validating condition [%+v]", cond)
	}
	err = ConvertConditionStringToIntFloatRegexV2(&c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func handleInterfaceArray(node interface{}, parentString string) (Node, error) {
	v2 := node.([]interface{})
	nodes, err := getNodeByParentString(parentString)

	if err != nil {
		return nil, err
	}
	for _, subNode := range (v2) {
		subNode2, err := InterpretNode(subNode, "") // recursion!
		if err != nil {
			return nil, fmt.Errorf("can't parse subNode [%+v]", subNode)
		}
		nodes.Append(subNode2)
	}
	return nodes, nil
}

func getNodeByParentString(parentString string) (Node, error) {
	switch parentString {

	case "AND":
		return &And{}, nil

	case "OR":
		return &Or{}, nil

	case "ANY":
		return &Any{}, nil

	//case "ALL":
	//	return &All{}, nil

	default:
		return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
	}
}

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc...
func ConvertFieldsToRegexV2(rule *RuleV2) error {

	if rule.AlreadyConvertedFieldsToRegexFlag == true { // convert once
		return nil
	}

	var err error

	rule.Sender.SenderList, err = ConvertStringToExpandedSenderReceiver(rule.Sender.SenderName, rule.Sender.SenderType)
	if err != nil {
		return err
	}
	rule.Receiver.ReceiverList, err = ConvertStringToExpandedSenderReceiver(rule.Receiver.ReceiverName, rule.Receiver.ReceiverType)
	if err != nil {
		return err
	}

	re, err := regexp.Compile(ConvertOperationStringToRegex(rule.Operation)) // a special case of regex for operations to support CRUD
	if err != nil {
		return err
	}
	rule.OperationRegex = re.Copy()

	re, err = regexp.Compile(ConvertStringToRegex(rule.Resource.ResourceName))
	if err != nil {
		return err
	}

	rule.Resource.ResourceNameRegex = re.Copy()
	rule.AlreadyConvertedFieldsToRegexFlag = true

	return nil

}

func PrepareRulesV2(rules *RulesV2) error {

	for i, _ := range (rules.Rules) {
		err := PrepareOneRuleV2(&rules.Rules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func PrepareOneRuleV2(rule *RuleV2) error {
	// prepare the rules for use (when loading from json not all the fields are ready...)
	/*
		err := ValidateRule(rule)
		if err != nil {
			return err
		}*/
	err := ConvertFieldsToRegexV2(rule)
	if err != nil {
		return err
	}
	// err = ConvertConditionStringToIntFloatRegexV2(rule) // prepare the label conditions
	return nil
}

func ConvertConditionStringToIntFloatRegexV2(condition *Condition) error { // TO-DO: cut to sub-functions

	originalAttribute := condition.Attribute
	if condition.Method == "IN" || condition.Method == "NIN" {

		tempString := strings.Replace(condition.Value, "[", "", -1)
		tempString = strings.Replace(tempString, "]", "", -1)
		tempString = strings.Replace(tempString, ",", "$|^", -1)
		tempString = "^" + tempString + "$"
		if condition.Method == "IN" {
			condition.Method = "RE"
		}
		if condition.Method == "NIN" {
			condition.Method = "NRE"
		}
		condition.Value = tempString
		condition.Value = tempString
	}

	tempString, factor := convertStringWithUnits(condition.Value)
	valFloat, err := strconv.ParseFloat(tempString, 64)
	valFloat = valFloat * factor
	if err == nil {
		condition.ValueFloat = valFloat
	}
	valInt, err := strconv.ParseInt(condition.Value, 10, 64)
	if err == nil {
		condition.ValueInt = valInt
	}

	re, err := regexp.Compile(condition.Value)
	if err == nil {
		condition.ValueRegex = re.Copy() // this is used in RE,NRE
	}
	if err != nil && slice.ContainsString(regexSlice, condition.Method) {
		return fmt.Errorf("invalid regex string in condition")
	}

	re, err = regexp.Compile(ConvertStringToRegex(condition.Value))
	if err == nil {
		condition.ValueStringRegex = re.Copy() // this is used in EQ,NEQ
	} else {
		return fmt.Errorf("condition.Value could not be converted to regex")
	}

	if strings.Index(condition.Attribute, "senderLabel[") == 0 { // test if ATTRIBUTE is of type senderLabel
		condition.AttributeIsSenderLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeSenderLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "senderLabel"
		condition.OriginalAttribute = originalAttribute // used in hash
	}
	if strings.Index(condition.Attribute, "receiverLabel[") == 0 { // test if ATTRIBUTE is of type receiverLabel
		condition.AttributeIsReceiverLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeReceiverLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "receiverLabel"
		condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.Index(condition.Value, "receiverLabel[") == 0 { // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
		condition.ValueIsReceiverLabel = true
		i1 := strings.Index(condition.Value, "[") + 1
		i2 := strings.Index(condition.Value, "]")

		condition.ValueReceiverLabelKey = condition.Value[i1:i2]
		condition.Value = "receiverLabel"
		condition.OriginalValue = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Attribute, "$sender.") { // test if ATTRIBUTE is of type sender object
		condition.AttributeIsSenderObject = true
		i1 := strings.Index(condition.Attribute, ".") + 1
		condition.AttributeSenderObjectAttribute = condition.Attribute[i1:]
		condition.Attribute = "$sender"
		condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Attribute, "$receiver.") { // test if ATTRIBUTE is of type receiver object
		condition.AttributeIsReceiverObject = true
		i1 := strings.Index(condition.Attribute, ".") + 1
		condition.AttributeReceiverObjectAttribute = condition.Attribute[i1:]
		condition.Attribute = "$receiver"
		condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Value, "$receiver.") { // test if VALUE is of type receiver object (used to compare attribute of sender object to value of receiver object)
		condition.ValueIsReceiverObject = true
		i1 := strings.Index(condition.Value, ".") + 1
		condition.ValueReceiverObject = condition.Value[i1:]
		condition.Value = "$receiver"
		condition.OriginalValue = originalAttribute // used in hash
	}

	if strings.Index(condition.Attribute, "jsonpath:") == 0 { // test if ATTRIBUTE is of type jsonpath
		condition.AttributeIsJsonpath = true
		i1 := strings.Index(condition.Attribute, ":") + 1
		i2 := len(condition.Attribute)
		netConditionAttribute := condition.Attribute[i1:i2]
		if netConditionAttribute[0] == '.' {
			netConditionAttribute = "$" + netConditionAttribute
		}
		netConditionAttribute = strings.Replace(netConditionAttribute, "\"", "'", -1)
		condition.AttributeJsonpathQuery = netConditionAttribute
		condition.Attribute = "jsonpath"
		condition.OriginalAttribute = originalAttribute // used in hash
	}
	return nil
}
