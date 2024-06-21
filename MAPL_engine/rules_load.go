package MAPL_engine

import (
	"crypto/md5"
	"fmt"
	"github.com/toolkits/slice"
	"gopkg.in/getlantern/deepcopy.v1"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var GlobalPredefinedStringsAndLists PredefinedStringsAndLists

func SetGlobalPredefinedStringsAndLists(stringsAndlists PredefinedStringsAndLists) error {
	validatedStringsAndlists, err := validatePredefinedString(stringsAndlists)
	if err != nil {
		return err
	}
	GlobalPredefinedStringsAndLists = validatedStringsAndlists
	return nil
}

// YamlReadRulesFromString function reads rules from a yaml string
func YamlReadRulesFromString(yamlString string) (Rules, error) {

	var rules Rules
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return Rules{}, err
	}

	//err = PrepareRules(&rules)
	//err = PrepareRulesWithPredefinedStrings(&rules, PredefinedStringsAndLists{})
	//if err != nil {
	//	return Rules{}, err
	//}

	return rules, nil
}

func YamlReadRulesFromFile(filename string) (Rules, error) {

	filename = strings.Replace(filename, "\\", "/", -1)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Rules{}, err
	}

	err = testYaml(data)
	if err != nil {
		return Rules{}, err
	}

	rules, err := YamlReadRulesFromString(string(data))
	return rules, err
}

func (rule *Rule) SetPredefinedStringsAndLists(stringsAndlists PredefinedStringsAndLists) error {

	rule.ruleAlreadyPrepared = false

	var ruleCopy Rule
	err := deepcopy.Copy(&ruleCopy, rule)
	if err != nil {
		return err
	}

	rule.predefinedStringsAndLists = stringsAndlists

	err = PrepareOneRuleWithPredefinedStrings(&ruleCopy, rule.predefinedStringsAndLists)
	if err != nil {
		return err
	}

	ruleCopy.ruleAlreadyPrepared = true
	rule.preparedRule = &ruleCopy
	rule.ruleAlreadyPrepared = true

	return nil
}

func (rule *Rule) GetPreparedRule() *Rule { // used in unit tests

	if !rule.ruleAlreadyPrepared {
		r := Rule{}
		return &r
	}
	return rule.preparedRule

}

func YamlReadRulesFromStringWithPredefinedStrings(yamlString string, stringsAndlists PredefinedStringsAndLists) (Rules, error) {

	var rules Rules
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return Rules{}, err
	}

	for i_r, _ := range rules.Rules {
		err = rules.Rules[i_r].SetPredefinedStringsAndLists(stringsAndlists)
		if err != nil {
			return Rules{}, err
		}
	}

	//err = PrepareRulesWithPredefinedStrings(&rules, stringsAndlists)
	//if err != nil {
	//	return Rules{}, err
	//}

	return rules, nil
}

func YamlReadRulesFromFileWithPredefinedStrings(filename string, stringsAndlists PredefinedStringsAndLists) (Rules, error) {

	filename = strings.Replace(filename, "\\", "/", -1)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Rules{}, err
	}

	err = testYaml(data)
	if err != nil {
		return Rules{}, err
	}

	rules, err := YamlReadRulesFromStringWithPredefinedStrings(string(data), stringsAndlists)
	return rules, err
}

func testYaml(data []byte) error {
	var z interface{}
	return yaml.UnmarshalStrict(data, &z)
}

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc...
func ConvertFieldsToRegex(rule *Rule) error {

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

	re, err = regexp.Compile(ConvertStringToRegex(rule.Resource.ResourceName, "WithWildcards")) // we allow automatic use of wildcards in ResourceName attribute
	if err != nil {
		return err
	}

	rule.Resource.ResourceNameRegex = re.Copy()
	rule.AlreadyConvertedFieldsToRegexFlag = true

	return nil

}

func PrepareRules(rules *Rules) error {

	for i, _ := range rules.Rules {
		err := PrepareOneRule(&rules.Rules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func PrepareOneRule(rule *Rule) error {
	// prepare the rules for use (when loading from json not all the fields are ready...)
	// also do some validation on fields other than the conditions

	err := ConvertFieldsToRegex(rule)
	if err != nil {
		return err
	}
	return nil
}

func PrepareRulesWithPredefinedStrings(rules *Rules, stringsAndLists PredefinedStringsAndLists) error {

	for i, _ := range rules.Rules {
		err := PrepareOneRuleWithPredefinedStrings(&rules.Rules[i], stringsAndLists)
		if err != nil {
			return err
		}
	}
	return nil
}

func PrepareOneRuleWithPredefinedStrings(rule *Rule, stringsAndLists PredefinedStringsAndLists) error {
	// prepare the rules for use (when loading from json not all the fields are ready...)
	// also do some validation on fields other than the conditions

	if rule.Conditions.ConditionsTree != nil {
		err := rule.Conditions.ConditionsTree.PrepareAndValidate(stringsAndLists)
		if err != nil {
			return err
		}
	}

	err := ReplaceStringsAndListsInOneRule(rule, stringsAndLists)
	if err != nil {
		return err
	}
	err = ConvertFieldsToRegex(rule)
	if err != nil {
		return err
	}
	return nil
}

func ReplaceStringsAndListsInOneRule(rule *Rule, stringsAndLists PredefinedStringsAndLists) error {

	newList, ok, isReplaceable := isReplaceableList(rule.Sender.SenderName, stringsAndLists)
	if ok {
		rule.Sender.SenderName = convertListToString(newList)
	} else {
		val, ok := isReplaceableString(rule.Sender.SenderName, stringsAndLists)
		if ok {
			rule.Sender.SenderName = val
		}
		if isReplaceable && !ok {
			return fmt.Errorf("sender name is not predefined [%v]", rule.Sender.SenderName)
		}
	}

	newList, ok, isReplaceable = isReplaceableList(rule.Receiver.ReceiverName, stringsAndLists)
	if ok {
		rule.Receiver.ReceiverName = convertListToString(newList)
	} else {
		val, ok := isReplaceableString(rule.Receiver.ReceiverName, stringsAndLists)
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
	newList, ok, isReplaceable := isReplaceableList(c.Value, stringsAndlists)
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
		newValue, ok := isReplaceableString(c.Value, stringsAndlists)
		if ok {
			c.Value = newValue
		} else {
			if isReplaceable {
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

func isReplaceableString(x string, stringsAndlists PredefinedStringsAndLists) (string, bool) {
	if strings.HasPrefix(x, "#") {
		x = strings.Replace(x, "#", "", 1)
		val, ok := stringsAndlists.PredefinedStrings[x]
		if ok {
			return val, ok
		}
	}
	return "", false
}

func isReplaceableList(x string, stringsAndlists PredefinedStringsAndLists) ([]string, bool, bool) {
	if strings.HasPrefix(x, "#") {
		x = strings.Replace(x, "#", "", 1)
		list, ok := stringsAndlists.PredefinedListsWithoutRefs[x]
		if ok {
			return list, ok, true
		} else {
			return []string{}, false, true
		}
	}
	return []string{}, false, false
}

func ConvertConditionStringToIntFloatRegex(condition *Condition) error { // TO-DO: cut to sub-functions
	condition.OriginalAttribute = condition.Attribute
	condition.OriginalMethod = condition.Method
	condition.OriginalValue = condition.Value

	if condition.Method == "IN" || condition.Method == "NIN" || condition.Method == "IS" {
		tempString := strings.Replace(condition.Value, "[", "", -1)
		tempString = strings.Replace(tempString, "]", "", -1)
		tempString = strings.Replace(tempString, ",", "$|^", -1)
		tempString = "^" + tempString + "$"
		if condition.Method == "IN" || condition.Method == "IS" {
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
		condition.ValueFloat = &valFloat
	}
	valInt, err := strconv.ParseInt(condition.Value, 10, 64)
	if err == nil {
		condition.ValueInt = &valInt
	}

	re, err := regexp.Compile(condition.Value)
	if err == nil {
		condition.ValueRegex = re.Copy() // this is used in RE,NRE
	}
	if err != nil && slice.ContainsString(regexSlice, condition.Method) {
		return fmt.Errorf("invalid regex string in condition")
	}

	re, err = regexp.Compile(ConvertStringToRegex(condition.Value, condition.OriginalMethod))
	flagError := false
	if err == nil {
		condition.ValueStringRegex = re.Copy() // this is used in EQ,NEQ in non-jsonpath fields (for example, we allow wildcards in strings there)
	} else {
		condition.ValueStringRegex = nil
		flagError = true
	}

	// now, handle attributes of types senderLabel,receiverLabel, $sender, $receiver, jsonpath
	handleSenderReceiverLabelsAttribute(condition)
	handleSenderReceiverAttributes(condition)
	handleJsonpathAttribute(condition)

	if condition.AttributeIsJsonpath || condition.AttributeIsJsonpathRelative {
		return nil
	}
	if flagError {
		return fmt.Errorf("condition.Value could not be converted to regex")
	}

	return nil
}

func handleSenderReceiverLabelsAttribute(condition *Condition) {
	//originalAttribute := condition.Attribute
	//originalValue := condition.Value
	if strings.HasPrefix(condition.Attribute, "senderLabel[") { // test if ATTRIBUTE is of type senderLabel
		condition.AttributeIsSenderLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeSenderLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "senderLabel"
		//condition.OriginalAttribute = originalAttribute // used in hash
	}
	if strings.HasPrefix(condition.Attribute, "receiverLabel[") { // test if ATTRIBUTE is of type receiverLabel
		condition.AttributeIsReceiverLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeReceiverLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "receiverLabel"
		//condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Value, "receiverLabel[") { // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
		condition.ValueIsReceiverLabel = true
		i1 := strings.Index(condition.Value, "[") + 1
		i2 := strings.Index(condition.Value, "]")

		condition.ValueReceiverLabelKey = condition.Value[i1:i2]
		condition.Value = "receiverLabel"
		//condition.OriginalValue = originalValue // used in hash
	}
}

func handleSenderReceiverAttributes(condition *Condition) {
	//originalAttribute := condition.Attribute
	//originalValue := condition.Value
	if strings.HasPrefix(condition.Attribute, "$sender.") { // test if ATTRIBUTE is of type sender object
		condition.AttributeIsSenderObject = true
		i1 := strings.Index(condition.Attribute, ".") + 1
		condition.AttributeSenderObjectAttribute = condition.Attribute[i1:]
		condition.Attribute = "$sender"
		//condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Attribute, "$receiver.") { // test if ATTRIBUTE is of type receiver object
		condition.AttributeIsReceiverObject = true
		i1 := strings.Index(condition.Attribute, ".") + 1
		condition.AttributeReceiverObjectAttribute = condition.Attribute[i1:]
		condition.Attribute = "$receiver"
		//condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Value, "$receiver.") { // test if VALUE is of type receiver object (used to compare attribute of sender object to value of receiver object)
		condition.ValueIsReceiverObject = true
		i1 := strings.Index(condition.Value, ".") + 1
		condition.ValueReceiverObject = condition.Value[i1:]
		condition.Value = "$receiver"
		//condition.OriginalValue = originalValue // used in hash
	}
}

func handleJsonpathAttribute(condition *Condition) {
	//originalAttribute := condition.Attribute
	if strings.HasPrefix(condition.Attribute, "jsonpath:") { // test if ATTRIBUTE is of type jsonpath
		condition.AttributeIsJsonpath = true
		i1 := strings.Index(condition.Attribute, ":") + 1
		i2 := len(condition.Attribute)
		netConditionAttribute := condition.Attribute[i1:i2]

		condition.AttributeIsJsonpathRelative = false
		relativeKeywords := []string{"$RELATIVE.", "$KEY", "$VALUE"}
		if SliceHasPrefix(relativeKeywords, netConditionAttribute) {
			condition.AttributeIsJsonpathRelative = true
			netConditionAttribute = strings.Replace(netConditionAttribute, "$RELATIVE.", "$.", 1)
			//netConditionAttribute = strings.Replace(netConditionAttribute, "$VALUE.", "$.", 1)
		} else {
			if netConditionAttribute == "$RELATIVE" {
				condition.AttributeIsJsonpathRelative = true
				netConditionAttribute = "$"
			}
		}

		if netConditionAttribute[0] == '.' {
			netConditionAttribute = "$" + netConditionAttribute
		}

		netConditionAttribute = RemoveDotQuotes(netConditionAttribute)

		//netConditionAttribute = strings.Replace(netConditionAttribute, "\"", "'", -1)
		netConditionAttribute = strings.Replace(netConditionAttribute, "'", "\"", -1)
		netConditionAttribute = strings.Replace(netConditionAttribute, ".[", "[", -1)
		condition.AttributeJsonpathQuery = netConditionAttribute
		condition.Attribute = "jsonpath"
		//condition.OriginalAttribute = originalAttribute // used in hash
	}
}

/*
func (rule *Rule) prepareOneRuleWithPredefinedStrings() {

	if !rule.ruleAlreadyPrepared {
		PrepareOneRuleWithPredefinedStrings(rule, rule.predefinedStringsAndLists)
		rule.ruleAlreadyPrepared = true
	}
}
*/

func RuleToString(rule Rule) string {

	strMainPart := "<" + strings.ToLower(rule.Decision) + ">-<" + strings.ToLower(rule.Sender.SenderType) + ":" + rule.Sender.SenderName + ">-<" + strings.ToLower(rule.Receiver.ReceiverType) +
		":" + rule.Receiver.ReceiverName + ">-" + strings.ToLower(rule.Operation) + "-" + strings.ToLower(rule.Protocol) + "-<" + rule.Resource.ResourceType + "-" + rule.Resource.ResourceName + ">"

	ruleStr := strMainPart + "-" + RuleConditionsToString(rule)

	return ruleStr
}
func (rule Rule) String() string {
	return RuleToString(rule)
}

func RuleConditionsToString(rule Rule) string {
	if rule.Conditions.ConditionsTree != nil {
		conditionsString := rule.Conditions.ConditionsTree.String()
		return conditionsString
	} else {
		return "no conditions"
	}
}

func RuleMD5Hash(rule Rule) (md5hash string) {

	ruleStr := RuleToString(rule)
	data := []byte(ruleStr)
	md5hash = fmt.Sprintf("%x", md5.Sum(data))

	return md5hash
}

func RuleMD5HashConditions(rule Rule) (md5hash string) {

	totalDNFstring := RuleConditionsToString(rule)
	data := []byte(totalDNFstring)
	md5hash = fmt.Sprintf("%x", md5.Sum(data))

	return md5hash
}

func (r Rule) ConditionsEqual(rule Rule) bool {
	return RuleMD5HashConditions(r) == RuleMD5HashConditions(rule)
}

func (rule *Rule) ToLower() {
	rule.Sender.SenderType = strings.ToLower(rule.Sender.SenderType)
	rule.Receiver.ReceiverType = strings.ToLower(rule.Receiver.ReceiverType)
	rule.Resource.ResourceType = strings.ToLower(rule.Resource.ResourceType)
	rule.Protocol = strings.ToLower(rule.Protocol)
	rule.Operation = strings.ToLower(rule.Operation)
	rule.Decision = strings.ToLower(rule.Decision)
}

func ValidateRule(rule *Rule) error {

	rule2 := Rule{}
	err := deepcopy.Copy(&rule2, rule)
	if err != nil {
		return fmt.Errorf("can't test validity of rule conditions")
	}
	err = ConvertFieldsToRegex(&rule2)
	if err != nil {
		return err
	}

	if rule2.Conditions.ConditionsTree != nil {
		err = rule2.Conditions.ConditionsTree.PrepareAndValidate(PredefinedStringsAndLists{})
		if err != nil {
			return err
		}
	}
	return nil
}
