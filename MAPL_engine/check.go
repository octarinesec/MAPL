// Package MAPL_enginge provides an engine to test messages against policy rules written in MAPL.
package MAPL_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhmj/jsonslice"
	"github.com/tidwall/pretty"
	"github.com/yalp/jsonpath"
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

func Check(message *MessageAttributes, rules *Rules) (decision int, descisionString string, relevantRuleIndex int, results []int, appliedRulesIndices []int, ruleDescription string, checkExtraData [][]map[string]interface{}) {
	//
	// for each message we check its attributes against all of the rules and return a decision
	//

	N := len(rules.Rules)

	results = make([]int, N)
	ruleDescriptions := make([]string, N)
	checkExtraData = make([][]map[string]interface{}, N)

	sem := make(chan int, N) // semaphore pattern
	if false {               // check in parallel

		for i, rule := range rules.Rules { // check all the rules in parallel
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

	} else { // used only for debugging

		for in_i, in_rule := range rules.Rules {
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
func CheckOneRule(message *MessageAttributes, ruleOriginal *Rule) (int, []map[string]interface{}) {

	if !ruleOriginal.ruleAlreadyPrepared {
		ruleOriginal.SetPredefinedStringsAndLists(GlobalPredefinedStringsAndLists) // use the global if not set already
	}
	rule := ruleOriginal.preparedRule // the prepared rule is the one used below!
	// ----------------------
	// compare basic message attributes:

	match := TestSender(rule, message)
	if !match {
		return DEFAULT, []map[string]interface{}{}
	}

	match = TestReceiver(rule, message)
	if !match {
		return DEFAULT, []map[string]interface{}{}
	}

	match = rule.OperationRegex.Match([]byte(message.RequestMethod)) // supports wildcards
	if !match {
		return DEFAULT, []map[string]interface{}{}
	}

	// ----------------------
	// compare resource:
	if rule.Protocol == "tcp" {
		match = rule.Resource.ResourceNameRegex.Match([]byte(message.DestinationPort))
		if !match {
			return DEFAULT, []map[string]interface{}{}
		}
	} else {
		if rule.Protocol != "*" {
			if !strings.EqualFold(message.ContextProtocol, rule.Protocol) { // regardless of case // need to support wildcards!
				return DEFAULT, []map[string]interface{}{}
			}

			if rule.Resource.ResourceType != "*" {
				if message.ContextType != rule.Resource.ResourceType { // need to support wildcards?
					return DEFAULT, []map[string]interface{}{}
				}
			}
			match = rule.Resource.ResourceNameRegex.Match([]byte(message.RequestPath)) // supports wildcards
			if !match {
				return DEFAULT, []map[string]interface{}{}
			}
		}
	}

	// ----------------------
	// test conditions:
	conditionsResult := true // if there are no conditions then we skip the test and return the rule.Decision
	extraData := []map[string]interface{}{}
	if rule.Conditions.ConditionsTree != nil {
		conditionsResult, extraData = TestConditions(ruleOriginal, message) // using original rule here. using prepared rule inside.
	}
	if conditionsResult == false {
		return DEFAULT, []map[string]interface{}{}
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
	return DEFAULT, []map[string]interface{}{}
}

func (rule *Rule) Check(message *MessageAttributes) (int, []map[string]interface{}) {
	return CheckOneRule(message, rule)
}

func TestSender(rule *Rule, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	match := false
	for _, expandedSender := range rule.Sender.SenderList {
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
	for _, expandedReceiver := range rule.Receiver.ReceiverList {
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
func TestConditions(rule *Rule, message *MessageAttributes) (bool, []map[string]interface{}) { // to-do return error

	if !rule.ruleAlreadyPrepared {
		rule.SetPredefinedStringsAndLists(GlobalPredefinedStringsAndLists)
	}

	if rule.preparedRule.Conditions.ConditionsTree != nil {
		return rule.preparedRule.Conditions.ConditionsTree.Eval(message)
	}
	return false, []map[string]interface{}{}

}

func (rule *Rule) TestConditions(message *MessageAttributes) (bool, []map[string]interface{}) {
	return TestConditions(rule, message)
}

// testOneCondition tests one condition of the rule with the message attributes
func testOneCondition(c *Condition, message *MessageAttributes) (bool, []map[string]interface{}) {

	var valueToCompareInt int64
	var valueToCompareFloat float64
	var valueToCompareString string

	result := false
	// select type of test by types of attribute and methods
	switch c.Attribute {
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
		return testSenderAttributeCondition(c, message), []map[string]interface{}{}

	case ("$receiver"):
		return testReceiverAttributeCondition(c, message), []map[string]interface{}{}

	case ("senderLabel"):
		return testSenderLabelCondition(c, message), []map[string]interface{}{}

	case ("receiverLabel"):
		return testReceiverLabelCondition(c, message), []map[string]interface{}{}

	case ("jsonpath"):
		var flag bool
		if message.RequestRawInterface != nil && c.PreparedJsonpathQuery != nil {
			flag = testJsonPathConditionOnInterface(c, message)
		} else {
			flag = testJsonPathCondition(c, message)
		}
		if flag && c.ReturnValueJsonpath != nil {
			extraDataTemp := getExtraData(c, message)
			return flag, []map[string]interface{}{extraDataTemp}
		}
		return flag, []map[string]interface{}{}

	default:
		log.Printf("condition keyword not supported: %+v\n", c) // was log.Fatalf
		return false, []map[string]interface{}{}
	}
	return result, []map[string]interface{}{}
}
func getExtraData(c *Condition, message *MessageAttributes) map[string]interface{} {
	if message.RequestRawInterface != nil {
		return getExtraDataFromInterface(c.PreparedReturnValueJsonpathQuery, c.PreparedReturnValueJsonpathQueryRelativeFlag, c.ReturnValueJsonpath, message)
	}
	return getExtraDataFromByteArray(c.ReturnValueJsonpath, c.PreparedReturnValueJsonpathQueryRelativeFlag, message)
}

func getExtraDataFromInterface(preparedReturnValueJsonpathQueryMap map[string]jsonpath.FilterFunc, preparedReturnValueJsonpathQueryRelativeFlag map[string]bool, returnValueJsonpathMap map[string]string, message *MessageAttributes) map[string]interface{} {
	extraDataTemp := make(map[string]interface{})

	for queryName, preparedQuery := range preparedReturnValueJsonpathQueryMap {
		if returnValueJsonpathMap[queryName] == "$*" {
			if preparedReturnValueJsonpathQueryRelativeFlag[queryName] {
				extraDataTemp[queryName] = *message.RequestRawInterfaceRelative
			} else {
				extraDataTemp[queryName] = *message.RequestRawInterface
			}
		} else {
			if preparedQuery != nil {
				var err error
				var extraDataTempTemp interface{}
				if preparedReturnValueJsonpathQueryRelativeFlag[queryName] {
					extraDataTempTemp, err = queryInterface(preparedQuery, *message.RequestRawInterfaceRelative)
				} else {
					extraDataTempTemp, err = queryInterface(preparedQuery, *message.RequestRawInterface)
				}
				if err == nil {
					extraDataTemp[queryName] = extraDataTempTemp
				}

			} else {
				var x interface{}
				extraDataTemp[queryName] = x
			}
		}
	}
	return extraDataTemp
}

func getExtraDataFromByteArray(returnValueJsonpathMap map[string]string, returnValueJsonpathQueryRelativeFlag map[string]bool, message *MessageAttributes) map[string]interface{} {
	extraDataTemp := make(map[string]interface{})

	for queryName, queryString := range returnValueJsonpathMap {
		var extraDataBytes []byte

		if returnValueJsonpathQueryRelativeFlag[queryName] {
			extraDataBytes, _ = jsonslice.Get(*message.RequestJsonRawRelative, queryString)
		} else {
			extraDataBytes, _ = jsonslice.Get(*message.RequestJsonRaw, queryString)
		}

		var tempInterface interface{}
		err := json.Unmarshal(extraDataBytes, &tempInterface)
		if err == nil {
			extraDataTemp[queryName] = tempInterface
		}
	}

	return extraDataTemp
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
	result := false
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
	result := false
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

	valueToCompareString = removeQuotesAndBrackets(valueToCompareString)
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
				result = compareStringFunc(valueToCompareString, c.Method, c.Value) // compare strings (strightforward comparison. use of wildcards is only via RE)
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

func testJsonPathConditionOnInterface(c *Condition, message *MessageAttributes) bool {

	if c.AttributeIsJsonpath == false {
		log.Println("jsonpath without the correct format")
		return false
	}

	var valueToCompareInterface interface{}
	var err = errors.New("error")

	if c.AttributeIsJsonpathRelative {
		if (*message).RequestRawInterfaceRelative == nil {
			return false // By definition
		}
		if c.AttributeJsonpathQuery == "$KEY" || strings.HasPrefix(c.AttributeJsonpathQuery, "$VALUE") {
			valueToCompareInterface, err = getKeyValueFromInterface(c, message)
		} else {
			valueToCompareInterface, err = queryInterface(c.PreparedJsonpathQuery, *message.RequestRawInterfaceRelative)
		}
	} else {
		if (*message).RequestRawInterface == nil {
			return false //by definition
		}
		valueToCompareInterface, err = queryInterface(c.PreparedJsonpathQuery, *message.RequestRawInterface)
	}

	if err != nil {
		if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
			return true
		}
		return false
	}

	var valueToCompareString string
	switch valueToCompareInterface.(type) {
	case map[string]interface{}, []interface{}:
		jsonBytes, _ := json.Marshal(valueToCompareInterface)
		valueToCompareString = string(jsonBytes)
	default:
		valueToCompareString = fmt.Sprintf("%v", valueToCompareInterface)
	}

	if len(valueToCompareString) == 0 || valueToCompareString == "<nil>" {
		return whatToReturnInCaseOfEmptyResult(*c)
	}

	valueToCompareString = removeQuotesAndBrackets(valueToCompareString)
	if len(valueToCompareString) == 0 {
		return whatToReturnInCaseOfEmptyResult(*c)
	}

	valueToCompareString, ok := removeQuotesFromResult(valueToCompareString)
	{
		if !ok {
			return false
		}
	}

	result := false
	method := strings.ToUpper(c.Method)
	switch method {
	case "GE", "GT", "LE", "LT", "EQ", "NEQ", "NE":
		flagCompareToNumber := false
		var valueToCompareFloat float64
		if c.ValueInt != nil || c.ValueFloat != nil {
			valueStringWithoutUnits, factor := convertStringWithUnits(valueToCompareString) // if the conversion to float doesn't work we still want to use the original string so we use a temporary one
			valueToCompareFloat, err = strconv.ParseFloat(valueStringWithoutUnits, 64)
			if err != nil {
				log.Println("can't parse jsonpath value [float]")
				if method == "NEQ" {
					return true
				}
				return false
			}
			valueToCompareFloat = valueToCompareFloat * factor
			flagCompareToNumber = true
		}

		if !flagCompareToNumber {
			if method == "EQ" || method == "NEQ" {
				//return compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex) // compare strings with wildcards
				return compareStringFunc(valueToCompareString, c.Method, c.Value) // compare strings (strightforward comparison. use of wildcards is only via RE)
			} else {
				return false // can't compare non-number
			}
		} else {
			return compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)
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

func getKeyValueFromInterface(c *Condition, message *MessageAttributes) (interface{}, error) {
	var valueToCompareInterface interface{}
	var err error
	if c.AttributeJsonpathQuery == "$KEY" {
		xx := (*message).RequestRawInterfaceRelative
		yy := (*xx).(map[string]interface{})
		for k := range yy {
			valueToCompareInterface = k
			err = nil
			break
		}
	} else {

		xx := (*message).RequestRawInterfaceRelative
		yy := (*xx).(map[string]interface{})
		for _, v := range yy {
			if c.AttributeJsonpathQuery == "$VALUE" {
				valueToCompareInterface = v
				err = nil
				break
			} else {
				valueToCompareInterface, err = queryInterface(c.PreparedJsonpathQuery, v)
				break
			}
		}
	}
	return valueToCompareInterface, err
}

func queryInterface(preparedJsonpathQuery jsonpath.FilterFunc, rawInterface interface{}) (interface{}, error) {
	valueToCompareInterface, err := preparedJsonpathQuery(rawInterface)
	if err != nil {
		errString := err.Error()
		if strings.Contains(errString, `not found in JSON object at`) {
			err = nil
		}
	}
	return valueToCompareInterface, err
}

func whatToReturnInCaseOfEmptyResult(c Condition) bool {
	if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
		return true
	}
	return false // default test result is false on an empty jsonpath result
}

func getKeyValue(jsonRaw []byte, attribute string) ([]byte, error) {
	//used only with byte array raw data. for interface raw data we use another method.
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
func compareIntFunc(value1 int64, method string, value2 *int64) bool { //value2 is the reference value from the rule
	switch method {
	case "EQ", "eq":
		return (value1 == *value2)
	case "NEQ", "neq", "ne", "NE":
		return (value1 != *value2)
	case "LE", "le":
		return (value1 <= *value2)
	case "LT", "lt":
		return (value1 < *value2)
	case "GE", "ge":
		return (value1 >= *value2)
	case "GT", "gt":
		return (value1 > *value2)
	}
	return false
}

// compareFloatFunc compares one float value according the method string.
func compareFloatFunc(value1 float64, method string, value2 *float64) bool { //value2 is the reference value from the rule
	switch method {
	case "EQ", "eq":
		return (value1 == *value2)
	case "NEQ", "neq", "ne", "NE":
		return (value1 != *value2)
	case "LE", "le":
		return (value1 <= *value2)
	case "LT", "lt":
		return (value1 < *value2)
	case "GE", "ge":
		return (value1 >= *value2)
	case "GT", "gt":
		return (value1 > *value2)
	}
	return false
}

// compareStringFunc compares one string value according the method string
func compareStringFunc(value1 string, method string, value2 string) bool {
	switch method {
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
		switch method {
		case "EQ", "eq":
			return false
		case "NEQ", "neq", "ne", "NE":
			return true
		}
	}

	switch method {

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
		switch method {
		case "RE", "re":
			return false
		case "NRE", "nre":
			return true
		}
	}

	switch method {
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

func getArrayOfInterfaces(a AnyAllNode, message *MessageAttributes) ([]interface{}, error) {
	// used in eval of ANY/ALL node (getting the data from the message raw interface attributes by the parentJsonpath)

	var arrayDataInterface interface{}
	err := errors.New("error")
	parentJsonpath := a.GetParentJsonpathAttribute()
	if strings.HasPrefix(parentJsonpath, "$RELATIVE.") || parentJsonpath == "$RELATIVE*" || strings.HasPrefix(parentJsonpath, "$KEY.") || strings.HasPrefix(parentJsonpath, "$VALUE.") { // to-do: create a flag once when parsing!

		if parentJsonpath == "$RELATIVE*" {
			var temp []interface{}
			xx := (*message).RequestRawInterfaceRelative
			yy := (*xx).(map[string]interface{})
			for k, v := range yy {
				zz := make(map[string]interface{}, 1)
				zz[k] = v
				temp = append(temp, zz)
			}
			return temp, nil
		}

		returnArray := []interface{}{}
		for _, jsonpathQueryFunc := range a.GetPreparedJsonpathQuery() {
			arrayDataInterface, err = jsonpathQueryFunc(*message.RequestRawInterfaceRelative)
			a := ArrangeArrayInterface(arrayDataInterface)
			for _, aa := range a {
				returnArray = append(returnArray, aa)
			}
		}
		return returnArray, nil
	} else {
		returnArray := []interface{}{}
		for _, jsonpathQueryFunc := range a.GetPreparedJsonpathQuery() {
			arrayDataInterface, err = jsonpathQueryFunc(*message.RequestRawInterface)
			a := ArrangeArrayInterface(arrayDataInterface)
			for _, aa := range a {
				returnArray = append(returnArray, aa)
			}
		}
		return returnArray, nil
	}
	if arrayDataInterface != nil {
		return ArrangeArrayInterface(arrayDataInterface), nil
	}
	return []interface{}{}, err
}

func ArrangeArrayInterface(arrayDataInterface interface{}) []interface{} {
	switch arrayDataInterface.(type) {
	case map[string]interface{}:
		tempArray := arrayDataInterface.(map[string]interface{})
		tempArrayOut := []interface{}{}
		for k, v := range tempArray {
			tempArrayOut = append(tempArrayOut, map[string]interface{}{k: v})
		}
		return tempArrayOut
	default:
		if arrayDataInterface == nil {
			return []interface{}{}
		}
		tempArray := arrayDataInterface.([]interface{})
		tempArrayOut := []interface{}{}
		for _, x := range tempArray {
			switch x.(type) {
			case []interface{}: // in case of deepscan we get [][]interface{} and not []interface{}. here we re-arrange it.
				tempArray2 := x.([]interface{})
				for _, y := range tempArray2 {
					tempArrayOut = append(tempArrayOut, y)
				}
			default:
				return tempArray
			}
		}
		return tempArrayOut
	}
}

func getArrayOfJsons(a AnyAllNode, message *MessageAttributes) ([][]byte, error) {
	// used in eval of ANY/ALL node (getting the data from the message attributes by the parentJsonpath)
	arrayData := []byte{}
	arrayDataTemp := []byte{}

	err := errors.New("error")
	parentJsonpathList := a.GetParentJsonpathAttributeArray()
	for _, parentJsonpath := range parentJsonpathList {
		if strings.HasPrefix(parentJsonpath, "$RELATIVE.") || parentJsonpath == "$RELATIVE*" || strings.HasPrefix(parentJsonpath, "$KEY.") || strings.HasPrefix(parentJsonpath, "$VALUE.") { // to-do: create a flag once when parsing!
			parentJsonpath = strings.Replace(parentJsonpath, "$RELATIVE.", "$.", 1)
			parentJsonpath = strings.Replace(parentJsonpath, "$KEY.", "$.", 1) // to do: this is not supported. remove
			parentJsonpath = strings.Replace(parentJsonpath, "$VALUE.", "$.", 1)
			if parentJsonpath == "$RELATIVE*" {
				parentJsonpath = "$*"
			}
			arrayDataTemp, err = jsonslice.Get(*message.RequestJsonRawRelative, parentJsonpath)
		} else {
			arrayDataTemp, err = jsonslice.Get(*message.RequestJsonRaw, parentJsonpath)
		}
		if err == nil {
			if len(arrayData) == 0 {
				arrayData = arrayDataTemp
			} else {
				if len(arrayDataTemp) != 0 {
					arrayData = append(arrayData, ',')
					arrayData = append(arrayData, arrayDataTemp...)
				}
			}
		}
	}

	if err != nil {
		return [][]byte{}, err
	}

	arrayData, err = getArrayFromArrayOfArrays(arrayData)
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

func getArrayOfJsonsFromInterfaceArrayOriginal(arrayData []byte) ([][]byte, error) {
	var arrayInterface []interface{}
	arrayJson := [][]byte{}
	err := json.Unmarshal([]byte(arrayData), &arrayInterface)
	if err != nil {
		return [][]byte{}, err
	}
	for _, x := range arrayInterface {
		y, err := json.Marshal(x)
		if err != nil {
			return [][]byte{}, err
		}
		arrayJson = append(arrayJson, y)
	}
	return arrayJson, nil
}

func getArrayOfJsonsFromInterfaceArray(arrayData []byte) ([][]byte, error) {
	// faster then getArrayOfJsonsFromInterfaceArrayOriginal
	// by a factor of about 20

	if len(arrayData) == 0 {
		return [][]byte{}, nil
	}

	if arrayData[0] == '{' { // this is not array of jsons ( []interface{} ) but map of jsons ( map[string]interface{} )
		return [][]byte{}, fmt.Errorf("not array of jsons")
	}

	arrayJson := [][]byte{}
	c := 0
	start := -1
	for i := 0; i < len(arrayData); i++ {
		if arrayData[i] == '{' {
			if c == 0 {
				start = i
			}
			c += 1
		}
		if arrayData[i] == '}' {
			c -= 1
		}
		if c == 0 {
			if start == -1 {
				continue
			}
			y := arrayData[start : i+1]
			start = -1
			arrayJson = append(arrayJson, y)
		}
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
	for i_x, x := range arrayInterface {
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

func getArrayFromArrayOfArrays(arrayData []byte) ([]byte, error) {
	if len(arrayData) < 2 {
		return arrayData, nil
	}

	/*  slow. we should use "pretty.Ugly" instead
	buffer := new(bytes.Buffer) // clean the json
	err := json.Compact(buffer, arrayData)
	if err != nil {
		return []byte{}, err
	}
	arrayDataNew = buffer.Bytes()
	*/

	arrayDataNew := pretty.Ugly(arrayData) // faster then json.Compact by a factor of ~6

	if arrayDataNew[0] != '[' || arrayDataNew[1] != '[' {
		return arrayDataNew, nil
	}

	arrayDataString := string(arrayDataNew)
	arrayDataString = strings.Replace(arrayDataString, "[[", "[", 1)
	arrayDataString = strings.Replace(arrayDataString, "]]", "]", 1)
	arrayDataString = strings.Replace(arrayDataString, "],[", ",", -1)

	if strings.Contains(arrayDataString, "[[") || strings.Contains(arrayDataString, "]]") {
		return []byte{}, fmt.Errorf("malformed arrayData")
	}
	return []byte(arrayDataString), nil
}
