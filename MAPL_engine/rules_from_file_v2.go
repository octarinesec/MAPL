package MAPL_engine

import (
	"crypto/md5"
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

	//err = PrepareRulesV2(&rules)
	err = PrepareRulesWithPredefinedStrings(&rules, PredefinedStringsAndLists{})
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

func YamlReadRulesFromStringWithPredefinedStrings(yamlString string, stringsAndlists PredefinedStringsAndLists) (RulesV2, error) {

	var rules RulesV2
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return RulesV2{}, err
	}

	err = PrepareRulesWithPredefinedStrings(&rules, stringsAndlists)
	if err != nil {
		return RulesV2{}, err
	}

	return rules, nil
}

func YamlReadRulesFromFileWithPredefinedStrings(filename string, stringsAndlists PredefinedStringsAndLists) (RulesV2, error) {

	filename = strings.Replace(filename, "\\", "/", -1)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return RulesV2{}, err
	}

	err = testYaml(data)
	if err != nil {
		return RulesV2{}, err
	}

	rules, err := YamlReadRulesFromStringWithPredefinedStrings(string(data), stringsAndlists)
	return rules, err
}

func testYaml(data []byte) error {
	var z interface{}
	return yaml.UnmarshalStrict(data, &z)
}

/*
func ParseAndValidateConditions(rule *RuleV2) error {

	if rule.Conditions.ConditionsTree == nil {
		return nil
	}
	c := rule.Conditions

	conditionsTree, err := ParseConditionsTree(c)
	if err != nil {
		return err
	}

	rule.Conditions.ConditionsTree = conditionsTree

	return nil
}
*/

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
	// also do some validation on fields other than the conditions

	err := ConvertFieldsToRegexV2(rule)
	if err != nil {
		return err
	}
	return nil
}


func PrepareRulesWithPredefinedStrings(rules *RulesV2,stringsAndLists PredefinedStringsAndLists) error {

	for i, _ := range (rules.Rules) {
		err := PrepareOneRuleWithPredefinedStrings(&rules.Rules[i],stringsAndLists)
		if err != nil {
			return err
		}
	}
	return nil
}

func PrepareOneRuleWithPredefinedStrings(rule *RuleV2,stringsAndLists PredefinedStringsAndLists) error {
	// prepare the rules for use (when loading from json not all the fields are ready...)
	// also do some validation on fields other than the conditions

	if rule.Conditions.ConditionsTree != nil {
		err := rule.Conditions.ConditionsTree.PrepareAndValidate(stringsAndLists)
		if err != nil {
			return err
		}
	}

	err:=ReplaceStringsAndListsInOneRule(rule, stringsAndLists)
	if err != nil {
		return err
	}
	err = ConvertFieldsToRegexV2(rule)
	if err != nil {
		return err
	}
	return nil
}

/*
func ReplaceStringsAndListsInRules(rules *RulesV2, stringsAndlists PredefinedStringsAndLists) error {

	for i, _ := range (rules.Rules) {
		err := ReplaceStringsAndListsInOneRule(&rules.Rules[i], stringsAndlists)
		if err != nil {
			return err
		}
	}
	return nil
}
*/
func ReplaceStringsAndListsInOneRule(rule *RuleV2, stringsAndLists PredefinedStringsAndLists) error {

	newList, ok, isReplaceable := isReplacebleList(rule.Sender.SenderName, stringsAndLists)
	if ok {
		rule.Sender.SenderName = convertListToString(newList)
	} else {
		val, ok := isReplacebleString(rule.Sender.SenderName, stringsAndLists)
		if ok {
			rule.Sender.SenderName = val
		}
		if isReplaceable && !ok{
			return fmt.Errorf("sender name is not predefined [%v]",rule.Sender.SenderName)
		}
	}

	newList, ok,isReplaceable = isReplacebleList(rule.Receiver.ReceiverName, stringsAndLists)
	if ok {
		rule.Receiver.ReceiverName = convertListToString(newList)
	} else {
		val, ok := isReplacebleString(rule.Receiver.ReceiverName, stringsAndLists)
		if ok {
			rule.Receiver.ReceiverName = val
		}
		if isReplaceable && !ok {
			return fmt.Errorf("receiver name is not predefined [%v]", rule.Receiver.ReceiverName)
		}
	}
	return nil
}
func ReplaceStringsAndListsInCondition(c *Condition, stringsAndlists PredefinedStringsAndLists) error {
	newList, ok,isReplaceable := isReplacebleList(c.Value, stringsAndlists)
	if ok {
		newValue := ""
		if c.Method == "RE" || c.Method == "NRE" {
			newValue = convertListToRegexString(newList)
			_, err := regexp.Compile(newValue)
			if err != nil {
				return err
			}
		} else {
			newValue = convertListToString(newList)
		}
		c.Value = newValue
	} else {
		newValue, ok := isReplacebleString(c.Value, stringsAndlists)
		if ok {
			c.Value = newValue
		}else{
			if isReplaceable{
				return fmt.Errorf("condition value is not predefined [%v]", c.Value)
			}
		}
	}
	return nil
}
func convertListToString(list []string) string {
	str := strings.Join(list, ",")
	return str
}

func convertListToRegexString(list []string) string {
	str := strings.Join(list, "|")
	return str
}

func isReplacebleString(x string, stringsAndlists PredefinedStringsAndLists) (string, bool) {
	if strings.HasPrefix(x, "#") {
		x = strings.Replace(x, "#", "", -1)
		val, ok := stringsAndlists.PredefinedStrings[x]
		if ok {
			return val, ok
		}
	}
	return "", false
}

func isReplacebleList(x string, stringsAndlists PredefinedStringsAndLists) ([]string, bool,bool) {
	if strings.HasPrefix(x, "#") {
		x = strings.Replace(x, "#", "", -1)
		keys, ok := stringsAndlists.PredefinedLists[x]
		if ok {
			list:=[]string{}
			for _,key:=range(keys){
				list=append(list,stringsAndlists.PredefinedStrings[key])
			}
			return list, ok,true
		}else{
			return []string{}, false,true
		}
	}
	return []string{}, false,false
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

		condition.AttributeIsJsonpathRelative = false
		if strings.Index(netConditionAttribute, "$relative.") == 0 {
			condition.AttributeIsJsonpathRelative = true
			netConditionAttribute = strings.Replace(netConditionAttribute, "$relative.", "$.", -1)
		}

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

func RuleToStringV2(rule RuleV2) string {

	strMainPart := "<" + strings.ToLower(rule.Decision) + ">-<" + strings.ToLower(rule.Sender.SenderType) + ":" + rule.Sender.SenderName + ">-<" + strings.ToLower(rule.Receiver.ReceiverType) +
		":" + rule.Receiver.ReceiverName + ">-" + strings.ToLower(rule.Operation) + "-" + strings.ToLower(rule.Protocol) + "-<" + rule.Resource.ResourceType + "-" + rule.Resource.ResourceName + ">"

	ruleStr := strMainPart
	if rule.Conditions.ConditionsTree != nil {
		conditionsString := rule.Conditions.ConditionsTree.String()
		ruleStr += "-" + conditionsString
	}

	return ruleStr
}

func RuleMD5HashV2(rule RuleV2) (md5hash string) {

	ruleStr := RuleToStringV2(rule)
	data := []byte(ruleStr)
	md5hash = fmt.Sprintf("%x", md5.Sum(data))

	return md5hash
}
