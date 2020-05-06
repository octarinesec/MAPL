// Package MAPL_enginge provides an engine to test messages against policy rules written in MAPL.
package MAPL_engine

import (
	"encoding/json"
	"fmt"
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

// Check is the main function to test if any of the rules is applicable for the message and decide according
// to those rules' decisions.

func Check(message *MessageAttributes, rules *Rules) (decision int, descisionString string, relevantRuleIndex int, results []int, appliedRulesIndices []int, ruleDescription string) {
	//
	// for each message we check its attributes against all of the rules and return a decision
	//

	N := len(rules.Rules)

	results = make([]int, N)
	ruleDescriptions := make([]string, N)
	sem := make(chan int, N) // semaphore pattern
	if true {                // check in parallel

		for i, rule := range (rules.Rules) { // check all the rules in parallel
			go func(in_i int, in_rule Rule) {
				results[in_i] = CheckOneRule(message, &in_rule)
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
			results[in_i] = CheckOneRule(message, &in_rule)
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

	return decision, descisionString, relevantRuleIndex, results, appliedRulesIndices, ruleDescription
}

// CheckOneRules gives the result of testing the message attributes with of one rule
func CheckOneRule(message *MessageAttributes, rule *Rule) int {
	// ----------------------
	// compare basic message attributes:

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	match := TestSender(rule, message)
	if !match {
		return DEFAULT
	}

	match = TestReceiver(rule, message)
	if !match {
		return DEFAULT
	}

	match = rule.OperationRegex.Match([]byte(message.RequestMethod)) // supports wildcards
	if !match {
		return DEFAULT
	}

	// ----------------------
	// compare resource:
	if rule.Protocol == "tcp" {
		match = rule.Resource.ResourceNameRegex.Match([]byte(message.DestinationPort))
		if !match {
			return DEFAULT
		}
	} else {
		if rule.Protocol != "*" {
			if !strings.EqualFold(message.ContextProtocol, rule.Protocol) { // regardless of case // need to support wildcards!
				return DEFAULT
			}

			if rule.Resource.ResourceType != "*" {
				if message.ContextType != rule.Resource.ResourceType { // need to support wildcards?
					return DEFAULT
				}
			}
			match = rule.Resource.ResourceNameRegex.Match([]byte(message.RequestPath)) // supports wildcards
			if !match {
				return DEFAULT
			}
		}
	}

	// ----------------------
	// test conditions:
	conditionsResult := true // if there are no conditions then we skip the test and return the rule.Decision
	if len(rule.DNFConditions) > 0 {
		conditionsResult = TestConditions(rule, message)
	}
	if conditionsResult == false {
		return DEFAULT
	}

	// ----------------------
	// if we got here then the rule applies and we use the rule's decision
	switch rule.Decision {
	case "allow", "ALLOW", "Allow":
		return ALLOW
	case "alert", "ALERT", "Alert":
		return ALERT
	case "block", "BLOCK", "Block":
		return BLOCK
	}
	return DEFAULT
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
func TestConditions(rule *Rule, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegex(rule)
	}

	dnfConditions := rule.DNFConditions
	res := make([]bool, len(dnfConditions))
	for i_andCondtions, andConditions := range (dnfConditions) {
		temp_res := true
		for _, condition := range (andConditions.ANDConditions) { // calculate AND clauses
			oneConditionResult := testOneCondition(&condition, message) // test one condition
			if oneConditionResult == false {
				temp_res = false
				break
			}
		}
		res[i_andCondtions] = temp_res
	}

	output := false // calculate OR of all the AND clauses
	for _, r := range (res) {
		output = output || r // logic OR
	}
	return output
}

// testOneCondition tests one condition of the rule with the message attributes
func testOneCondition(c *Condition, message *MessageAttributes) bool {
	// ---------------
	// currently we support the following attributes:
	// payloadSize
	// requestUseragent
	// utcHoursFromMidnight
	// ---------------
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
	case ("utcHoursFromMidnight"):
		valueToCompareFloat = message.RequestTimeHoursFromMidnightUTC
		result = compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)
	case ("minuteParity"):
		valueToCompareInt = message.RequestTimeMinutesParity
		result = compareIntFunc(valueToCompareInt, c.Method, c.ValueInt)
		fmt.Println("message.RequestTimeMinutesParity=", message.RequestTimeMinutesParity, valueToCompareInt, c.Method, c.ValueInt)

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

	case ("$sender"):

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

	case ("$receiver"):
		attributeReceiver := getAttribute("$receiver", c.AttributeReceiverObjectAttribute, *message)

		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(attributeReceiver, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(attributeReceiver, c.Method, c.ValueStringRegex) // string comparison with wildcards
		}

	case ("senderLabel"):
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
	case ("receiverLabel"):
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

	case ("domain"):
		valueToCompareString = message.Domain
		if c.Method == "RE" || c.Method == "re" || c.Method == "NRE" || c.Method == "nre" {
			result = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
		} else {
			result = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex)
		}

	case ("jsonpath"):

		if c.AttributeIsJsonpath == false {
			log.Println("jsonpath without the correct format")
			return false
		}

		if len(*message.RequestJsonRaw) == 0 {
			return false // this will create a change if something is true in the a new deployment
		}

		valueToCompareBytes, err := jsonslice.Get(*message.RequestJsonRaw, c.AttributeJsonpathQuery)
		if err != nil {
			if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
				return true
			}
			if c.Method == "EX" || c.Method == "ex" { // just test the existence of the key
				return false
			}
			return false
			//panic("jsonpath query failed")
		}

		expectedArrayLength := -1
		if strings.Contains(c.AttributeJsonpathQuery, "ontainers[:]") {
			ind := strings.Index(c.AttributeJsonpathQuery, "[:]")
			jsonpathQueryTemp := c.AttributeJsonpathQuery[0:ind]
			valueToCompareBytes2, err := jsonslice.Get(*message.RequestJsonRaw, jsonpathQueryTemp)

			if err == nil {

				keys := make([]interface{}, 0)
				json.Unmarshal(valueToCompareBytes2, &keys)
				expectedArrayLength = len(keys)

			}
		}

		valueToCompareString0 := string(valueToCompareBytes)

		if len(valueToCompareString0) == 0 {
			if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
				return true
			}
			return false // default test result is false on an empty jsonpath result

		}

		valueToCompareString0 = strings.Replace(valueToCompareString0, "[[", "[",-1)
		valueToCompareString0 = strings.Replace(valueToCompareString0, "]]", "]",-1)

		if valueToCompareString0 == "[]" {
			valueToCompareString0 = ""
		}

		if len(valueToCompareString0) == 0 {
			if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
				return true
			}
			return false // default test result is false on an empty jsonpath result
		}

		var valueToCompareStringArray []string
		L := len(valueToCompareString0) - 1
		if valueToCompareString0[0] == '[' && valueToCompareString0[L] == ']' {
			valueToCompareString0 = valueToCompareString0[1:L]
			valueToCompareStringArray = strings.Split(valueToCompareString0, ",")
		} else {
			valueToCompareStringArray = []string{valueToCompareString0}
		}

		if expectedArrayLength>=0 {
			if len(valueToCompareStringArray) != expectedArrayLength {
				if c.Method == "NEX" || c.Method == "nex" {
					//if len(valueToCompareStringArray) == 0 {
					return true
					//}
				}
				//return false
			}
		}else{
			if len(valueToCompareStringArray)==0{
				if c.Method == "NEX" {
					return true
				}
				if c.Method == "EX" {
					return false
				}
			} else{
				if c.Method == "NEX" {
					return false
				}
				if c.Method == "EX" {
					return true
				}
			}
		}
		/*
			if we have two jsonpath conditions that have array results then we test each one separately.
			(for example cpu limit and memory limit).
			so we don't test that ONE container has problem with the limits,
			but we do test that at least one container has problem with cpu limits
			and at least one container has problem with the memory limits.
			they don't have to be the same container.
		*/

		result = false // OR on values in the array. if one value in the array passes the condition then we return true

		for _, valueToCompareString := range (valueToCompareStringArray) {
			result_temp := false
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
				valueToCompareString2, factor := convertStringWithUnits(valueToCompareString) // if the conversion to float doesn't work we still want to use the original string so we use a temporary one
				valueToCompareFloat, err = strconv.ParseFloat(valueToCompareString2, 64)
				valueToCompareFloat = valueToCompareFloat * factor

				if err != nil {

					if method == "EQ" || method == "NEQ" {
						result_temp = compareStringWithWildcardsFunc(valueToCompareString, c.Method, c.ValueStringRegex) // compare strings with wildcards
					} else {
						log.Println("can't parse jsonpath value [float]")
						return false
					}
				} else {
					result_temp = compareFloatFunc(valueToCompareFloat, c.Method, c.ValueFloat)
				}
			case "RE", "NRE":
				result_temp = compareRegexFunc(valueToCompareString, c.Method, c.ValueRegex)
			case "EX", "NEX":
				if len(valueToCompareString) == 0 {
					if method == "NEX" { // just test the existence of the key
						return true
					}
					if method == "EX" { // just test the existence of the key
						return false
					}
				} else {
					if method == "NEX" { // just test the existence of the key
						return false
					}
					if method == "EX" { // just test the existence of the key
						return true
					}
				}

			default:
				log.Printf("method not supported: %v", method)
				return false
			}

			result = result || result_temp
		}

	default:
		log.Printf("condition keyword not supported: %+v", c) // was log.Fatalf
		return false
	}
	return result
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

	if value2==nil{
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

	if value2 == nil{
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
