// Package MAPL_enginge provides an engine to test messages against policy rules written in MAPL.
package MAPL_engine

import (
	"encoding/json"
	"errors"
	"github.com/bhmj/jsonslice"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// general action codes
const (
	DEFAULT int = iota
	ALLOW
	ALERT
	BLOCK
	NONE
)

var DecisionNames = [...]string{
	DEFAULT: "rules do not apply to message - block by default",
	ALLOW:   "allow",
	ALERT:   "alert",
	BLOCK:   "block",
	NONE:    "none",
}

func Check(message *MessageAttributes, rules *Rules) (decision int, descisionString string, relevantRuleIndex int, results []int, appliedRulesIndices []int, ruleDescription string, checkExtraData []string) {
	//
	// for each message we check its attributes against all of the rules and return a decision
	//

	N := len(rules.Rules)

	results = make([]int, N)
	ruleDescriptions := make([]string, N)
	checkExtraData = make([]string, N)

	sem := make(chan int, N) // semaphore pattern
	if true {                // check in parallel

		for i, rule := range (rules.Rules) { // check all the rules in parallel
			go func(in_i int, in_rule Rule) {
				results[in_i], checkExtraData[in_i] = CheckOneRule(message, &in_rule)
				if desc, ok := in_rule.Metadata["description"]; ok {
					ruleDescriptions[in_i] = desc
				} else {
					ruleDescriptions[in_i] = ""
				}
				sem <- 1 // mark that the one rule check is finished
			}(i, rule)

		}

		// wait for all goroutines to finish
		for i := 0; i < N; i++ {
			<-sem
		}

	} else { // used for debugging

		for in_i, in_rule := range (rules.Rules) {
			results[in_i], checkExtraData[in_i] = CheckOneRule(message, &in_rule)
			if desc, ok := in_rule.Metadata["description"]; ok {
				ruleDescriptions[in_i] = desc
			} else {
				ruleDescriptions[in_i] = ""
			}
		}
	}

	// go over the results and test by order of precedence
	appliedRulesIndices = make([]int, 0)
	relevantRuleIndex = -1

	max_decision := DEFAULT
	ruleDescription = ""
	for i := 0; i < N; i++ {
		if results[i] > DEFAULT {
			appliedRulesIndices = append(appliedRulesIndices, i)
		}
		if results[i] > max_decision {
			max_decision = results[i]
			ruleDescription = ruleDescriptions[i]
			relevantRuleIndex = i
		}
	}
	decision = max_decision
	descisionString = DecisionNames[decision]

	return decision, descisionString, relevantRuleIndex, results, appliedRulesIndices, ruleDescription, checkExtraData
}

// CheckOneRules gives the result of testing the message attributes with of one rule
func CheckOneRule(message *MessageAttributes, rule *Rule) (int, string) {
	// ----------------------
	// compare basic message attributes:

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	match := TestSender(rule, message)
	if !match {
		return DEFAULT, ""
	}

	match = TestReceiver(rule, message)
	if !match {
		return DEFAULT, ""
	}

	match = rule.OperationRegex.Match([]byte(message.RequestMethod)) // supports wildcards
	if !match {
		return DEFAULT, ""
	}

	// ----------------------
	// compare resource:
	if rule.Protocol == "tcp" {
		match = rule.Resource.ResourceNameRegex.Match([]byte(message.DestinationPort))
		if !match {
			return DEFAULT, ""
		}
	} else {
		if rule.Protocol != "*" {
			if !strings.EqualFold(message.ContextProtocol, rule.Protocol) { // regardless of case // need to support wildcards!
				return DEFAULT, ""
			}

			if rule.Resource.ResourceType != "*" {
				if message.ContextType != rule.Resource.ResourceType { // need to support wildcards?
					return DEFAULT, ""
				}
			}
			match = rule.Resource.ResourceNameRegex.Match([]byte(message.RequestPath)) // supports wildcards
			if !match {
				return DEFAULT, ""
			}
		}
	}

	// ----------------------
	// test conditions:
	conditionsResult := true // if there are no conditions then we skip the test and return the rule.Decision
	extraData := ""
	if rule.Conditions.ConditionsTree != nil {
		conditionsResult, extraData = TestConditions(rule, message)
	}
	if conditionsResult == false {
		return DEFAULT, ""
	}

	// ----------------------
	// if we got here then the rule applies and we use the rule's decision
	switch rule.Decision {
	case "allow", "ALLOW", "Allow":
		return ALLOW, extraData
	case "alert", "ALERT", "Alert":
		return ALERT, extraData
	case "block", "BLOCK", "Block":
		return BLOCK, extraData
	}
	return DEFAULT, ""
}

func TestSender(rule *Rule, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	match := false
	for _, expandedSender := range (rule.Sender.SenderList) {
		match_temp := false

		switch expandedSender.Type {
		case "subnet":
			if expandedSender.IsIP {
				match_temp = (expandedSender.Name == message.SourceIp)
			}
			if expandedSender.IsCIDR {
				match_temp = expandedSender.CIDR.Contains(message.SourceNetIp)
			}
		case "*", "workload":
			match_temp = expandedSender.Regexp.Match([]byte(message.SourceService)) // supports wildcards
		default:
			log.Println("type not supported")
			return false
		}
		if match_temp == true {
			match = true
			break
		}
	}
	return match
}

func TestReceiver(rule *Rule, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	match := false
	for _, expandedReceiver := range (rule.Receiver.ReceiverList) {
		match_temp := false

		switch expandedReceiver.Type {
		case "subnet":
			if expandedReceiver.IsIP {
				match_temp = (expandedReceiver.Name == message.DestinationIp)
			}
			if expandedReceiver.IsCIDR {
				match_temp = expandedReceiver.CIDR.Contains(message.DestinationNetIp)
			}
		case "hostname":
			match_temp = expandedReceiver.Regexp.Match([]byte(message.RequestHost)) // supports wildcards
		case "*", "workload":
			match_temp = expandedReceiver.Regexp.Match([]byte(message.DestinationService)) // supports wildcards
		default:
			log.Printf("%+v\n", rule)
			log.Printf("type not supported")
			return false

		}

		if match_temp == true {
			match = true
			break
		}
	}
	return match
}

// testConditions tests the conditions of the rule with the message attributes
func TestConditions(rule *Rule, message *MessageAttributes) (bool, string) { // to-do return error

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}
	if rule.Conditions.ConditionsTree!=nil {
		return rule.Conditions.ConditionsTree.Eval(message)
	}
	return false,"nil conditions"

}

// testOneCondition tests one condition of the rule with the message attributes
func testOneCondition(c *Condition, message *MessageAttributes) bool {

	var valueToCompareInt int64
	var valueToCompareFloat float64
	var valueToCompareString string

	result := false
	// select type of test by types of attribute and methods
	switch (c.Attribute) {
	case "true", "TRUE":
		result = true

	case "false", "FALSE":
		result = false

	case ("payloadSize"):
		valueToCompareInt = message.RequestSize
		result = compareIntFunc(valueToCompareInt, c.Method, c.ValueInt)

	case ("requestUseragent"):
		valueToCompareString = message.RequestUseragent
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex)
		}

	case ("utcHoursFromMidnight"): // used for debugging conditions
		valueToCompareFloat = message.RequestTimeHoursFromMidnightUTC
		result = compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)

	case ("encryptionType"):
		valueToCompareString = message.EncryptionType
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex)
		}

	case ("encryptionVersion"):
		valueToCompareFloat = *message.EncryptionVersion
		result = compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)

	case ("domain"):
		valueToCompareString = message.Domain
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex)
		}

	case ("$sender"):
		return testSenderAttributeCondition(c, message)

	case ("$receiver"):
		return testReceiverAttributeCondition(c, message)

	case ("senderLabel"):
		return testSenderLabelCondition(c, message)

	case ("receiverLabel"):
		return testReceiverLabelCondition(c, message)

	case ("jsonpath"):
		return testJsonPathCondition(c, message)

	default:
		log.Printf("condition keyword not supported: %+v\n", c) // was log.Fatalf
		return false
	}
	return result
}

func testSenderAttributeCondition(c *Condition, message *MessageAttributes) bool {

	result := false
	attributeSender := getAttribute("$sender", c.AttributeSenderObjectAttribute, *message)

	if c.ValueIsReceiverObject {
		valReceiver := getAttribute("$receiver", c.ValueReceiverObject, *message)
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			log.Println("wrong method with comparison of sender and receiver objects")
			return false
		}
		result = compareStringFunc(attributeSender, c.Method, valReceiver) // string comparison without wildcards
	} else {
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(attributeSender, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(attributeSender, c.Method, c.ValueStringRegex) // string comparison with wildcards
		}
	}
	return result

}

func testReceiverAttributeCondition(c *Condition, message *MessageAttributes) bool {

	result := false
	attributeReceiver := getAttribute("$receiver", c.AttributeReceiverObjectAttribute, *message)

	if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
		result = compareRegexFunc(attributeReceiver, c.Method, c.ValueRegex)
	} else {
		result = compareStringWithWildcardsFunc(attributeReceiver, c.Method, c.ValueStringRegex) // string comparison with wildcards
	}
	return result
}

func testSenderLabelCondition(c *Condition, message *MessageAttributes) bool {
	result:=false
	if c.AttributeIsSenderLabel == false {
		log.Println("senderLabel without the correct format")
		return false
	}
	if valueToCompareString1, ok := message.SourceLabels[c.AttributeSenderLabelKey]; ok { // enter the block only if the key exists
		if c.ValueIsReceiverLabel {
			if valueToCompareString2, ok2 := message.DestinationLabels[c.ValueReceiverLabelKey]; ok2 {
				if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
					log.Println("wrong method with comparison of two labels")
					return false
				}
				result = compareStringFunc(valueToCompareString1, c.Method, valueToCompareString2) // string comparison without wildcards
			}
		} else {
			if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
				result = compareRegexFunc(valueToCompareString1, c.Method, c.ValueRegex)
			} else {
				if c.Method == "EX" || c.Method == "ex" { // just test the existence of the key
					result = true
				} else {
					result = compareStringWithWildcardsFunc(valueToCompareString1, c.Method, c.ValueStringRegex) // string comparison with wildcards
				}
			}
		}
	}
	return result
}

func testReceiverLabelCondition(c *Condition, message *MessageAttributes) bool {
	result:=false
	if c.AttributeIsReceiverLabel == false {
		log.Println("receiverLabel without the correct format")
		return false
	}
	if valueToCompareString1, ok := message.DestinationLabels[c.AttributeReceiverLabelKey]; ok { // enter the block only if the key exists
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(valueToCompareString1, c.Method, c.ValueRegex)
		} else {
			if c.Method == "EX" || c.Method == "ex" { // just test the existence of the key
				result = true
			} else {
				result = compareStringWithWildcardsFunc(valueToCompareString1, c.Method, c.ValueStringRegex) // compare strings with wildcards
			}
		}
	}
	return result
}

func testJsonPathCondition(c *Condition, message *MessageAttributes) bool {

	if c.AttributeIsJsonpath == false {
		log.Println("jsonpath without the correct format")
		return false
	}
	valueToCompareBytes := []byte{}
	err := errors.New("error")
	if c.AttributeIsJsonpathRelative {
		if (*message).RequestJsonRawRelative == nil {
			return false // By definition
		}
		if len(*message.RequestJsonRawRelative) == 0 { // how to protect against nil pointer?
			return false // By definition. This will create a "change" if something is true in the a new deployment
		}
		if c.AttributeJsonpathQuery == "$KEY" || strings.HasPrefix(c.AttributeJsonpathQuery, "$VALUE") {
			valueToCompareBytes, err = getKeyValue(*message.RequestJsonRawRelative, c.AttributeJsonpathQuery)
			if strings.HasPrefix(c.AttributeJsonpathQuery, "$VALUE.") {
				tempQuery := strings.Replace(c.AttributeJsonpathQuery, "$VALUE.", "$.", 1)
				valueToCompareBytes, err = jsonslice.Get(valueToCompareBytes, tempQuery)
			}
		} else {
			valueToCompareBytes, err = jsonslice.Get(*message.RequestJsonRawRelative, c.AttributeJsonpathQuery)
		}
	} else {
		if (*message).RequestJsonRaw == nil {
			return false // By definition
		}
		if len(*message.RequestJsonRaw) == 0 {
			return false // By definition. This will create a "change" if something is true in the a new deployment
		}
		valueToCompareBytes, err = jsonslice.Get(*message.RequestJsonRaw, c.AttributeJsonpathQuery)
	}

	if err != nil {
		if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
			return true
		}
		return false
	}

	valueToCompareString := string(valueToCompareBytes)
	if len(valueToCompareString) == 0 {
		return whatToReturnInCaseOfEmptyResult(*c)
	}

	valueToCompareString=removeQuotesAndBrackets(valueToCompareString)
	if len(valueToCompareString) == 0 {
		return whatToReturnInCaseOfEmptyResult(*c)
	}

	result := false
	L := len(valueToCompareString) - 1
	if L > 0 {
		if valueToCompareString[0] == '"' && valueToCompareString[L] != '"' {
			log.Println("quotation marks not aligned")
			return false
		}
		if valueToCompareString[L] == '"' && valueToCompareString[0] != '"' {
			log.Println("quotation marks not aligned")
			return false
		}
		if valueToCompareString[L] == '"' && valueToCompareString[0] == '"' {
			valueToCompareString = valueToCompareString[1:L]
		}
	}

	method := strings.ToUpper(c.Method)
	switch method {
	case "GE", "GT", "LE", "LT", "EQ", "NEQ", "NE":
		valueStringWithoutUnits, factor := convertStringWithUnits(valueToCompareString) // if the conversion to float doesn't work we still want to use the original string so we use a temporary one
		valueToCompareFloat, err := strconv.ParseFloat(valueStringWithoutUnits, 64)
		valueToCompareFloat = valueToCompareFloat * factor

		if err != nil {
			if method == "EQ" || method == "NEQ" {
				result = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex) // compare strings with wildcards
			} else {
				log.Println("can't parse jsonpath value [float]")
				return false
			}
		} else {
			result = compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)
		}
	case "RE", "NRE":
		result = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
	case "EX", "NEX":
		if len(valueToCompareString) == 0 {
			return method == "NEX" // just test the existence of the key
		} else {
			return method == "EX" // just test the existence of the key
		}
	default:
		log.Printf("method not supported: %v", method)
		return false
	}

	return result
}

func whatToReturnInCaseOfEmptyResult(c Condition) bool {
	if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
		return true
	}
	return false // default test result is false on an empty jsonpath result
}

func removeQuotesAndBrackets(valueToCompareString string) string {
	valueToCompareString = strings.Replace(valueToCompareString, "[[", "[", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "]]", "]", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "[\"", "\"", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "\"]", "\"", -1)
	if valueToCompareString == "[]" {
		valueToCompareString = ""
	}
	return valueToCompareString
}

func getKeyValue(jsonRaw []byte, attribute string) ([]byte, error) {

	valueToCompareBytes := []byte{}
	var z map[string]interface{}
	err := json.Unmarshal(jsonRaw, &z)
	if err != nil {
		return []byte{}, err
	}
	keys := getKeys(z)
	if len(keys) != 1 {
		return []byte{}, err
	}
	if attribute == "$KEY" {
		valueToCompareBytes = []byte(keys[0])
	} else {
		z2, err := json.Marshal(z[keys[0]])
		if err != nil {
			return []byte{}, err
		}
		valueToCompareBytes = z2
	}
	return valueToCompareBytes, nil
}

func getAttribute(sender_receiver, attribute string, message MessageAttributes) string {
	switch attribute {
	case "namespace":
		if sender_receiver == "$sender" {
			return message.SourceNamespace
		} else {
			return message.DestinationNamespace
		}
	case "cluster":
		if sender_receiver == "$sender" {
			return message.SourceCluster
		} else {
			return message.DestinationCluster
		}
	}

	return ""

}

// compareIntFunc compares one int value according the method string.
func compareIntFunc(value1 int64, method string, value2 int64) bool { //value2 is the reference value from the rule
	switch (method) {
	case "EQ", "eq":
		return (value1 == value2)
	case "NEQ", "neq", "ne", "NE":
		return (value1 != value2)
	case "LE", "le":
		return (value1 <= value2)
	case "LT", "lt":
		return (value1 < value2)
	case "GE", "ge":
		return (value1 >= value2)
	case "GT", "gt":
		return (value1 > value2)
	}
	return false
}

// compareFloatFunc compares one float value according the method string.
func compareFloatFunc(value1 float64, method string, value2 float64) bool { //value2 is the reference value from the rule
	switch (method) {
	case "EQ", "eq":
		return (value1 == value2)
	case "NEQ", "neq", "ne", "NE":
		return (value1 != value2)
	case "LE", "le":
		return (value1 <= value2)
	case "LT", "lt":
		return (value1 < value2)
	case "GE", "ge":
		return (value1 >= value2)
	case "GT", "gt":
		return (value1 > value2)
	}
	return false
}

// compareStringFunc compares one string value according the method string
func compareStringFunc(value1 string, method string, value2 string) bool {
	switch (method) {
	case "EQ", "eq":
		return (value1 == value2)
	case "NEQ", "neq", "ne", "NE":
		return (value1 != value2)
	}
	return false
}

// compareStringWithWildcardsFunc compares one string value according the method string (supports wildcards)
func compareStringWithWildcardsFunc(value1 string, method string, value2 *regexp.Regexp) bool {
	//log.Printf("%v ?%v? %v",value1,method,value2)

	if value2 == nil {
		switch (method) {
		case "EQ", "eq":
			return false
		case "NEQ", "neq", "ne", "NE":
			return true
		}
	}

	switch (method) {

	case "EX", "ex":
		return len(value1) > 0
	case "NEX", "nex":
		return len(value1) == 0
	case "EQ", "eq":
		return (value2.MatchString(value1))
	case "NEQ", "neq", "ne", "NE":
		return !(value2.MatchString(value1))
	}
	return false

}

// compareRegexFunc compares one string value according the regular expression string.
func compareRegexFunc(value1 string, method string, value2 *regexp.Regexp) bool { //value2 is the reference value from the rule

	if value2 == nil {
		switch (method) {
		case "RE", "re":
			return false
		case "NRE", "nre":
			return true
		}
	}

	switch (method) {
	case "RE", "re":
		return (value2.MatchString(value1))
	case "NRE", "nre":
		return !(value2.MatchString(value1))
	}
	return false
}


//-------------------------------
// functions for Any/All Node
//-------------------------------
func getArrayOfJsons(a AnyAllNode, message *MessageAttributes) ([][]byte, error) {
	// used in eval of ANY/ALL node (getting the data from the message attributes by the parentJsonpath)
	arrayData := []byte{}
	err := errors.New("error")
	parentJsonpath := a.GetParentJsonpathAttribute()
	if strings.HasPrefix(parentJsonpath, "$RELATIVE.") || strings.HasPrefix(parentJsonpath, "$KEY.") || strings.HasPrefix(parentJsonpath, "$VALUE.") { // to-do: create a flag once when parsing!
		parentJsonpath = strings.Replace(parentJsonpath, "$RELATIVE.", "$.", 1)
		parentJsonpath = strings.Replace(parentJsonpath, "$KEY.", "$.", 1)
		parentJsonpath = strings.Replace(parentJsonpath, "$VALUE.", "$.", 1)
		arrayData, err = jsonslice.Get(*message.RequestJsonRawRelative, parentJsonpath)
	} else {
		arrayData, err = jsonslice.Get(*message.RequestJsonRaw, parentJsonpath)
	}

	if err != nil {
		return [][]byte{}, err
	}

	arrayJson, err := getArrayOfJsonsFromInterfaceArray(arrayData)
	if err != nil {
		arrayJson, err := getArrayOfJsonsFromMapStringInterface(arrayData)
		if err != nil {
			return [][]byte{}, err
		}
		return arrayJson, nil
	}
	return arrayJson, nil
}

func getArrayOfJsonsFromInterfaceArray(arrayData []byte) ([][]byte, error) {
	var arrayInterface []interface{}
	arrayJson := [][]byte{}
	err := json.Unmarshal([]byte(arrayData), &arrayInterface)
	if err != nil {
		return [][]byte{}, err
	}
	for _, x := range (arrayInterface) {
		y, err := json.Marshal(x)
		if err != nil {
			return [][]byte{}, err
		}
		arrayJson = append(arrayJson, y)
	}
	return arrayJson, nil
}

func getArrayOfJsonsFromMapStringInterface(arrayData []byte) ([][]byte, error) {
	var arrayInterface map[string]interface{}
	arrayJson := [][]byte{}
	err := json.Unmarshal([]byte(arrayData), &arrayInterface)
	if err != nil {
		return [][]byte{}, err
	}
	for i_x, x := range (arrayInterface) {
		z := map[string]interface{}{}
		z[i_x] = x
		y, err := json.Marshal(z)
		if err != nil {
			return [][]byte{}, err
		}
		arrayJson = append(arrayJson, y)
	}
	return arrayJson, nil
}
