package MAPL_engine

import (
	"crypto/md5"
	"fmt"
	"github.com/toolkits/slice"
	"gopkg.in/getlantern/deepcopy.v1"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// YamlReadRulesFromString function reads rules from a yaml string
func YamlReadRulesFromString(yamlString string) (Rules, error) {

	var rules Rules
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return Rules{}, err
	}

	//err = PrepareRules(&rules)
	err = PrepareRulesWithPredefinedStrings(&rules, PredefinedStringsAndLists{})
	if err != nil {
		return Rules{}, err
	}

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

func YamlReadRulesFromStringWithPredefinedStrings(yamlString string, stringsAndlists PredefinedStringsAndLists) (Rules, error) {

	var rules Rules
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Printf("error: %v", err)
		return Rules{}, err
	}

	err = PrepareRulesWithPredefinedStrings(&rules, stringsAndlists)
	if err != nil {
		return Rules{}, err
	}

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

	re, err = regexp.Compile(ConvertStringToRegex(rule.Resource.ResourceName))
	if err != nil {
		return err
	}

	rule.Resource.ResourceNameRegex = re.Copy()
	rule.AlreadyConvertedFieldsToRegexFlag = true

	return nil

}

func PrepareRules(rules *Rules) error {

	for i, _ := range (rules.Rules) {
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

	for i, _ := range (rules.Rules) {
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

	// now, handle attributes of types senderLabel,receiverLabel, $sender, $receiver, jsonpath
	handleSenderReceiverLabelsAttribute(condition)
	handleSenderReceiverAttributes(condition)
	handleJsonpathAttribute(condition)

	return nil
}

func handleSenderReceiverLabelsAttribute(condition *Condition) {
	originalAttribute := condition.Attribute
	if strings.HasPrefix(condition.Attribute, "senderLabel[") { // test if ATTRIBUTE is of type senderLabel
		condition.AttributeIsSenderLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeSenderLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "senderLabel"
		condition.OriginalAttribute = originalAttribute // used in hash
	}
	if strings.HasPrefix(condition.Attribute, "receiverLabel[") { // test if ATTRIBUTE is of type receiverLabel
		condition.AttributeIsReceiverLabel = true
		i1 := strings.Index(condition.Attribute, "[") + 1
		i2 := strings.Index(condition.Attribute, "]")

		condition.AttributeReceiverLabelKey = condition.Attribute[i1:i2]
		condition.Attribute = "receiverLabel"
		condition.OriginalAttribute = originalAttribute // used in hash
	}

	if strings.HasPrefix(condition.Value, "receiverLabel[") { // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
		condition.ValueIsReceiverLabel = true
		i1 := strings.Index(condition.Value, "[") + 1
		i2 := strings.Index(condition.Value, "]")

		condition.ValueReceiverLabelKey = condition.Value[i1:i2]
		condition.Value = "receiverLabel"
		condition.OriginalValue = originalAttribute // used in hash
	}
}

func handleSenderReceiverAttributes(condition *Condition) {
	originalAttribute := condition.Attribute
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
}


func handleJsonpathAttribute(condition *Condition) {
	originalAttribute := condition.Attribute
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
		}

		if netConditionAttribute[0] == '.' {
			netConditionAttribute = "$" + netConditionAttribute
		}

		netConditionAttribute = strings.Replace(netConditionAttribute, "\"", "'", -1)
		condition.AttributeJsonpathQuery = netConditionAttribute
		condition.Attribute = "jsonpath"
		condition.OriginalAttribute = originalAttribute // used in hash
	}
}

// convertStringToRegex function converts one string to regex. Remove spaces, handle special characters and wildcards.
func ConvertStringToRegex(str_in string) string {

	str_list := strings.Split(str_in, ",")

	str_out := "("
	L := len(str_list)

	for i_str, str := range (str_list) {
		str = strings.Replace(str, " ", "", -1)    // remove spaces
		str = strings.Replace(str, ".", "[.]", -1) // handle dot for conversion to regex
		str = strings.Replace(str, "$", "\\$", -1)
		str = strings.Replace(str, "^", "\\^", -1)
		str = strings.Replace(str, "*", ".*", -1)
		str = strings.Replace(str, "?", ".", -1)
		str = strings.Replace(str, "/", "\\/", -1)
		str = "^" + str + "$" // force full string
		if i_str < L-1 {
			str += "|"
		}
		str_out += str
	}
	str_out += ")"
	return str_out
}

func ConvertStringToExpandedSenderReceiver(str_in string, type_in string) ([]ExpandedSenderReceiver, error) {
	var output []ExpandedSenderReceiver

	str_list := strings.Split(str_in, ",")
	for _, str := range (str_list) {
		var e ExpandedSenderReceiver
		e.Name = str
		//e.IsIP,e.IsCIDR,e.IP,e.CIDR=isIpCIDR(str)
		e.Type = type_in
		if type_in == "subnet" {
			if str == "*" {
				str = "0.0.0.0/0"
			}
			e.IsIP, e.IsCIDR, e.IP, e.CIDR = isIpCIDR(str)
			if !e.IsIP && !e.IsCIDR {
				return []ExpandedSenderReceiver{}, fmt.Errorf("Type is 'subnet' but value is not an IP or CIDR")
			}
		}
		str = strings.Replace(str, " ", "", -1)    // remove spaces
		str = strings.Replace(str, ".", "[.]", -1) // handle dot for conversion to regex
		str = strings.Replace(str, "$", "\\$", -1)
		str = strings.Replace(str, "^", "\\^", -1)
		str = strings.Replace(str, "*", ".*", -1)
		str = strings.Replace(str, "?", ".", -1)
		str = strings.Replace(str, "/", "\\/", -1)
		str = "^" + str + "$" // force full string

		re, err := regexp.Compile(str)
		if err != nil {
			return []ExpandedSenderReceiver{}, fmt.Errorf("can't create regex of value in list: %v", err)
		}
		e.Regexp = re.Copy()
		output = append(output, e)
	}
	return output, nil
}

// convertOperationStringToRegex function converts the operations string to regex.
// this is a special case of convertStringToRegex
func ConvertOperationStringToRegex(str_in string) string {

	str_out := ""
	switch (str_in) {
	case "*":
		str_out = ".*"
	case "write", "WRITE":
		str_out = "(^POST$|^PUT$|^DELETE$)" // we cannot translate to ".*" because then rules of type "write:block" would apply to all messages.
	case "read", "READ":
		str_out = "(^GET$|^HEAD$|^OPTIONS$|^TRACE$|^read$|^READ$)"
	default:
		str_out = ConvertStringToRegex(str_in)
	}
	return str_out
}

func SliceHasPrefix(sl []string, v string) bool {
	for _, vv := range sl {
		if strings.HasPrefix(v, vv) {
			return true
		}
	}
	return false
}

func RuleToString(rule Rule) string {

	strMainPart := "<" + strings.ToLower(rule.Decision) + ">-<" + strings.ToLower(rule.Sender.SenderType) + ":" + rule.Sender.SenderName + ">-<" + strings.ToLower(rule.Receiver.ReceiverType) +
		":" + rule.Receiver.ReceiverName + ">-" + strings.ToLower(rule.Operation) + "-" + strings.ToLower(rule.Protocol) + "-<" + rule.Resource.ResourceType + "-" + rule.Resource.ResourceName + ">"

	ruleStr := strMainPart + "-" + RuleConditionsToString(rule)

	return ruleStr
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

func convertStringWithUnits(inputString string) (string, float64) {
	// see: https://en.wikipedia.org/wiki/Binary_prefix
	// also: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-memory

	factorVec := []float64{1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, math.Pow(1024, 2), math.Pow(1024, 3), math.Pow(1024, 4), math.Pow(1024, 5), math.Pow(1024, 6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001}
	strVec := []string{"e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"}

	for i_unit, unit := range strVec {

		flag1 := strings.HasSuffix(inputString, unit)
		flag2 := strings.Count(inputString, unit) == 1

		if flag1 && flag2 {
			outputString := strings.Replace(inputString, unit, "", -1)
			factor := factorVec[i_unit]
			return outputString, factor
		}
	}
	return inputString, 1.0

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

	if rule2.Conditions.ConditionsTree!=nil {
		err = rule2.Conditions.ConditionsTree.PrepareAndValidate(PredefinedStringsAndLists{})
		if err != nil {
			return err
		}
	}
	return nil
}
