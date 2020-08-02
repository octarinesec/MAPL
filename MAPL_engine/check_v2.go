// Package MAPL_enginge provides an engine to test messages against policy rules written in MAPL.
package MAPL_engine

import (
	"errors"
	"fmt"
	"github.com/bhmj/jsonslice"
	"log"
	"strconv"
	"strings"
)

func CheckV2(message *MessageAttributes, rules *RulesV2) (decision int, descisionString string, relevantRuleIndex int, results []int, appliedRulesIndices []int, ruleDescription string) {
	//
	// for each message we check its attributes against all of the rules and return a decision
	//

	N := len(rules.Rules)

	results = make([]int, N)
	ruleDescriptions := make([]string, N)
	sem := make(chan int, N) // semaphore pattern
	if false {               // check in parallel

		for i, rule := range (rules.Rules) { // check all the rules in parallel
			go func(in_i int, in_rule RuleV2) {
				results[in_i] = CheckOneRuleV2(message, &in_rule)
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
			results[in_i] = CheckOneRuleV2(message, &in_rule)
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
func CheckOneRuleV2(message *MessageAttributes, rule *RuleV2) int {
	// ----------------------
	// compare basic message attributes:

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegexV2(rule)
	}

	match := TestSenderV2(rule, message)
	if !match {
		return DEFAULT
	}

	match = TestReceiverV2(rule, message)
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
	if rule.Conditions.ConditionsTree != nil {
		conditionsResult = TestConditionsV2(rule, message)
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

func TestSenderV2(rule *RuleV2, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegexV2(rule)
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

func TestReceiverV2(rule *RuleV2, message *MessageAttributes) bool {

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegexV2(rule)
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
func TestConditionsV2(rule *RuleV2, message *MessageAttributes) bool { // to-do return error

	if rule.AlreadyConvertedFieldsToRegexFlag == false {
		ConvertFieldsToRegexV2(rule)
	}
	return rule.Conditions.ConditionsTree.Eval(message)

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
		return testJsonPathCondition(c, message)

	default:
		log.Printf("condition keyword not supported: %+v\n", c) // was log.Fatalf
		return false
	}
	return result
}

func testJsonPathCondition(c *Condition, message *MessageAttributes) bool {

	if c.AttributeIsJsonpath == false {
		log.Println("jsonpath without the correct format")
		return false
	}
	valueToCompareBytes:=[]byte{}
	err:=errors.New("error")
	if c.AttributeIsJsonpathRelative{
		if (*message).RequestJsonRawRelative==nil{
			return false // By definition
		}
		if len(*message.RequestJsonRawRelative) == 0 { // how to protect against nil pointer?
			return false // By definition. This will create a "change" if something is true in the a new deployment
		}
		valueToCompareBytes, err = jsonslice.Get(*message.RequestJsonRawRelative, c.AttributeJsonpathQuery)
	}else {
		if (*message).RequestJsonRaw==nil{
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
		if c.Method == "EX" || c.Method == "ex" { // just test the existence of the key
			return false
		}
		return false
	}

	valueToCompareString := string(valueToCompareBytes)

	if len(valueToCompareString) == 0 {
		if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
			return true
		}
		return false // default test result is false on an empty jsonpath result
	}

	valueToCompareString = strings.Replace(valueToCompareString, "[[", "[", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "]]", "]", -1)
	if valueToCompareString == "[]" {
		valueToCompareString = ""
	}

	if len(valueToCompareString) == 0 {
		if c.Method == "NEX" || c.Method == "nex" { // just test the existence of the key
			return true
		}
		return false // default test result is false on an empty jsonpath result
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
		valueToCompareString2, factor := convertStringWithUnits(valueToCompareString) // if the conversion to float doesn't work we still want to use the original string so we use a temporary one
		valueToCompareFloat, err := strconv.ParseFloat(valueToCompareString2, 64)
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

	return result
}
