package MAPL_engine

import (
	"fmt"
	"github.com/toolkits/slice"
	"regexp"
	"strconv"
	"strings"
)

var supportedMethodsSlice = []string{"ge", "GE", "gt", "GT", "le", "LE", "lt", "LT", "re", "RE", "nre", "NRE", "in", "IN", "nin", "NIN", "eq", "EQ", "neq", "NEQ", "ne", "NE", "ex", "EX", "nex", "NEX", "IS"}
var regexSlice = []string{"re", "nre", "RE", "NRE"}
var numberMethodSlice = []string{"ge", "GE", "gt", "GT", "le", "LE", "lt", "LT"}
var supportedAttributesPrefixes = []string{"$sender.", "$receiver.", "senderLabel[", "receiverLabel[", "jsonpath:"}
var supportedAttributesExact = []string{"true", "TRUE", "false", "FALSE", "payloadSize", "requestUseragent", "utcHoursFromMidnight", "encryptionType", "encryptionVersion", "domain"}
var allowedEncryptionVersionOperation = []string{"eq", "lt", "le", "gt", "ge", "EQ", "LT", "LE", "GT", "GE"}

// ValidateRuleConditions as much as possible
func ValidateOneCondition(condition *Condition) (bool, error) {

	flagAtt, err := validateAttribute(condition)
	if err != nil {
		return flagAtt, err
	}

	flagMethod, err := validateMethod(condition)
	if err != nil {
		return flagMethod, err
	}

	flagNumerical, err := convertAndValidateNumericalValues(condition)
	if err != nil {
		return flagNumerical, err
	}
	return true, nil
}

func validateAttribute(condition *Condition) (bool, error) {
	flagAtt := false
	for _, att := range supportedAttributesExact {
		if condition.Attribute == att {
			flagAtt = true
		}
	}
	for _, att := range supportedAttributesPrefixes {
		if strings.Index(condition.Attribute, att) == 0 {
			flagAtt = true
		}
	}
	if !flagAtt {
		return false, fmt.Errorf("invalid attribute in condition [%v]", condition.Attribute)
	}
	if condition.Attribute == "encryptionVersion" {
		if !slice.ContainsString(allowedEncryptionVersionOperation, condition.Method) {
			return false, fmt.Errorf("invalid method for attribute 'EncryptionVersion'")
		}
	}
	if strings.HasPrefix(condition.Attribute, "jsonpath:") {
		if (!strings.HasPrefix(condition.Attribute, "jsonpath:$") && !strings.HasPrefix(condition.Attribute, "jsonpath:.")) {
			return false, fmt.Errorf("jsonpath condition must start with '$' or '.' [%v]", condition.Attribute)
		}
		if strings.HasPrefix(condition.Attribute, "jsonpath:$") && !strings.HasPrefix(condition.Attribute, "jsonpath:$.") {
			relativeKeywords := []string{"jsonpath:$RELATIVE.", "jsonpath:$KEY", "jsonpath:$VALUE"}
			if !SliceHasPrefix(relativeKeywords, condition.Attribute) {
				if condition.Attribute != "jsonpath:$RELATIVE" {
					return false, fmt.Errorf("jsonpath condition must start with '$.' [%v]", condition.Attribute)
				}
			}
		}
		if strings.HasPrefix(condition.Attribute, "jsonpath:$KEY.") {
			return false, fmt.Errorf("jsonpath condition $KEY must not have a subfield [%v]", condition.Attribute)
		}
		if strings.Contains(condition.Attribute, "[:]") {
			return false, fmt.Errorf("jsonpath condition contains array reference. need to use parent node of type ANY/ALL")
		}
		if strings.Contains(condition.Attribute, "[]") {
			return false, fmt.Errorf("jsonpath condition contains empty square brackets")
		}
		if !validateArraysWithIndex(condition.Attribute) {
			return false, fmt.Errorf("jsonpath condition contains array reference (not an integer index). need to use parent node of type ANY/ALL")
		}

	}

	flagLabels, err := validateConditionOnLabels(condition)
	if err != nil {
		return flagLabels, err
	}

	flagSenderReceiverAtt, err := validateConditionOnSenderReceiverAttributes(condition)
	if err != nil {
		return flagSenderReceiverAtt, err
	}

	return true, nil

}

func validateArraysWithIndex(att string) bool {
	startIndex := 0
	for i := 0; i < len(att); i++ {
		if att[i] == '[' {
			startIndex = i
		}
		if att[i] == ']' {
			insideBrackets := att[startIndex+1 : i]

			if insideBrackets[0] == '"' && insideBrackets[len(insideBrackets)-1] == '"' { // we allow strings. example: jsonpath:$.metadata.labels['foo']
				continue
			}
			if insideBrackets[0] == '\'' && insideBrackets[len(insideBrackets)-1] == '\'' { // we allow strings. example: jsonpath:$.metadata.labels['foo']
				continue
			}

			num, err := strconv.Atoi(insideBrackets)
			if err != nil {
				return false
			}
			if num < 0 {
				return false
			}
		}
	}
	return true
}

func validateMethod(condition *Condition) (bool, error) {

	if !slice.ContainsString(supportedMethodsSlice, condition.Method) {
		return false, fmt.Errorf("invalid method in condition [%v]", condition.Method)
	}
	if condition.Method == "IN" || condition.Method == "NIN" {
		L := len(condition.Value)
		if L == 0 {
			return false, fmt.Errorf("test membership in empty array")
		}
		tempString := strings.Replace(condition.Value, "[", "", -1)
		tempString = strings.Replace(tempString, "]", "", -1)
		tempString = strings.Replace(tempString, ",", "$|^", -1)
		tempString = "^" + tempString + "$"

		_, err := regexp.Compile(tempString)
		if err != nil {
			return false, fmt.Errorf("condition.Value is not a valid array")
		}
	}
	return true, nil
}

func convertAndValidateNumericalValues(condition *Condition) (bool, error) {

	tempString, factor := convertStringWithUnits(condition.Value)
	isNum := false
	valFloat, err := strconv.ParseFloat(tempString, 64)
	valFloat = valFloat * factor
	if err == nil {
		condition.ValueFloat = &valFloat
		isNum = true
	}
	valInt, err := strconv.ParseInt(condition.Value, 10, 64)
	if err == nil {
		condition.ValueInt = &valInt
		isNum = true
	}

	if isNum == false && slice.ContainsString(numberMethodSlice, condition.Method) {
		return false, fmt.Errorf("invalid numerical value in condition")
	}

	_, err = regexp.Compile(condition.Value)
	if err != nil && slice.ContainsString(regexSlice, condition.Method) {
		return false, fmt.Errorf("invalid regex string in condition")
	}

	return true, nil

}

func validateConditionOnLabels(condition *Condition) (bool, error) {

	if strings.Index(condition.Attribute, "senderLabel[") == 0 { // test if ATTRIBUTE is of type senderLabel
		i2 := strings.Index(condition.Attribute, "]")
		if i2 < len(condition.Attribute)-1 {
			return false, fmt.Errorf("senderLabel has a wrong format")
		}
		if slice.ContainsString(numberMethodSlice, condition.Method) {
			return false, fmt.Errorf("numerical method with senderLabel")
		}
	}
	if strings.Index(condition.Attribute, "receiverLabel[") == 0 { // test if ATTRIBUTE is of type receiverLabel
		i2 := strings.Index(condition.Attribute, "]")
		if i2 < len(condition.Attribute)-1 {
			return false, fmt.Errorf("receiverLabel has a wrong format")
		}
		if slice.ContainsString(numberMethodSlice, condition.Method) {
			return false, fmt.Errorf("numerical method with receiverLabel")
		}
	}

	if strings.Index(condition.Value, "receiverLabel[") == 0 { // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
		i2 := strings.Index(condition.Value, "]")
		if i2 < len(condition.Value)-1 {
			return false, fmt.Errorf("value receiverLabel has a wrong format")
		}
	}
	return true, nil
}

func validateConditionOnSenderReceiverAttributes(condition *Condition) (bool, error) {

	if strings.HasPrefix(condition.Attribute, "$sender.") { // test if ATTRIBUTE is of type sender object
		if slice.ContainsString(numberMethodSlice, condition.Method) {
			return false, fmt.Errorf("numerical method with $sender")
		}
	}

	if strings.HasPrefix(condition.Attribute, "$receiver.") { // test if ATTRIBUTE is of type receiver object
		if slice.ContainsString(numberMethodSlice, condition.Method) {
			return false, fmt.Errorf("numerical method with $receiver")
		}
	}
	return true, nil
}
