package MAPL_engine

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)


type GeneralStruct interface {
	// a general interface to structures.
	ToJson() (string, error) // This function is used when comparing structures read from yaml files to the resulting fields in the structure.
}

// IsNumberOfFieldsEqual is used to compare the structures read from files (mostly while debugging).
// We convert the structure into a string and count the number of non-empty "fields". Then we compare to the number of non empty fields in the original yaml string.
// It will not work with structure fields with default values (for example ints or floats) so we remove them.
func IsNumberOfFieldsEqual(generalStruct GeneralStruct, yamlString string) (bool, string, error) {
	json_str, err := generalStruct.ToJson()
	if err != nil {
		return false, "", err
	}
	flag, output_string := compareJsonAndYaml(json_str, yamlString)
	return flag, output_string, nil
}

// compareJsonAndYaml counts the number of non-empty, non-integer, non-float fields in the jsonString.
// We remove fields known to non string values
func compareJsonAndYaml(jsonString string, yamlString string) (bool, string) {

	jsonString = strings.Replace(jsonString, "\"", "", -1)     // remove "
	jsonString = strings.Replace(jsonString, "null", "", -1)   // remove null
	jsonString = strings.Replace(jsonString, ",\n", "\n", -1)  // remove ',' at the end of a line
	jsonString = strings.Replace(jsonString, "{}\n", "\n", -1) // remove '{}' at the end of a line
	jsonString = strings.Replace(jsonString, "{\n", "\n", -1)  // remove '{' at the end of a line
	jsonString = strings.Replace(jsonString, "[\n", "\n", -1)  // remove '[' at the end of a line
	jsonString = strings.Replace(jsonString, "}\n", "\n", -1)  // remove '}' at the end of a line
	jsonString = strings.Replace(jsonString, "]\n", "\n", -1)  // remove ']' at the end of a line

	jsonString = strings.Replace(jsonString, "ValueInt:", "ValueInt-", -1)                                 // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "ValueFloat:", "ValueFloat-", -1)                             // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "ValueRegex:", "ValueRegex-", -1)                             // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "ValueTime:", "ValueTime-", -1)                               // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "UTC:", "UTC-", -1)                                           // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "RequestTimeMinutesParity:", "RequestTimeMinutesParity-", -1) // change slightly so that the regex will not count it [this field is not part of the input so disregard it]
	jsonString = strings.Replace(jsonString, "ContextType:", "ContextType-", -1)                           // change slightly so that the regex will not count it [this field is not part of the input so disregard it]

	jsonString = strings.Replace(jsonString, "Size: 0\n", "Size- 0\n", -1)                                   // change slightly so that the regex will not count it [this is an integer field]
	jsonString = strings.Replace(jsonString, "Duration: 0\n", "Duration- 0\n", -1)                           // change slightly so that the regex will not count it [this is an integer field]
	jsonString = strings.Replace(jsonString, "ResponseCode: 0\n", "ResponseCode- 0\n", -1)                   // change slightly so that the regex will not count it [this is an integer field]
	jsonString = strings.Replace(jsonString, "0001-01-01T00:00:00Z\n", "\n", -1)                             // change slightly so that the regex will not count it [this is a timestamp field]
	jsonString = strings.Replace(jsonString, "IpFlag: false\n", "IpFlag- false\n", -1)                       // change slightly so that the regex will not count it [this is boolean field]
	jsonString = strings.Replace(jsonString, "NetIp: ", "NetIp- ", -1)                                       // change slightly so that the regex will not count it [this is net.IP field]
	jsonString = strings.Replace(jsonString, "AttributeIsSenderLabel: ", "AttributeIsSenderLabel- ", -1)     // change slightly so that the regex will not count it [this is a boolean field]
	jsonString = strings.Replace(jsonString, "AttributeIsReceiverLabel: ", "AttributeIsReceiverLabel- ", -1) // change slightly so that the regex will not count it [this is a boolean field]
	jsonString = strings.Replace(jsonString, "ValueIsReceiverLabel: ", "ValueIsReceiverLabel- ", -1)         // change slightly so that the regex will not count it [this is a boolean field]
	jsonString = strings.Replace(jsonString, "SourceLabels: ", "SourceLabels- ", -1)                         // change slightly so that the regex will not count it [this is a map[string]string field]
	jsonString = strings.Replace(jsonString, "DestinationLabels: ", "DestinationLabels- ", -1)               // change slightly so that the regex will not count it [this is a map[string]string field]
	jsonString = strings.Replace(jsonString, "Regex: ", "Regex- ", -1)                                       // change slightly so that the regex will not count it [this is a map[string]string field]

	re, err := regexp.Compile(`(?m)^.*[:][ ]\S+`)
	if err != nil {
		return false, fmt.Sprintf("%v", err)
	}

	matches1 := re.FindAllString(yamlString, -1)
	matches2 := re.FindAllString(jsonString, -1)
	L3a := 0
	L3b := 0
	for _, s := range (matches1) {
		if strings.Index(s, "sender_label") >= 0 {
			re2, err := regexp.Compile("[[:alnum:]][:][[:alnum:]]") // catches fieldnam[e: v]alue'
			if err != nil {
				return false, fmt.Sprintf("%v", err)
			}
			matches3 := re2.FindAllString(s, -1)
			L3a += len(matches3)
		}
		if strings.Index(s, "receiver_label") >= 0 {

			re2, err := regexp.Compile("[[:alnum:]][:][[:alnum:]]") // catches fieldnam[e: v]alue'
			if err != nil {
				return false, fmt.Sprintf("%v", err)
			}
			matches3 := re2.FindAllString(s, -1)
			L3b += len(matches3)
		}
	}

	L1 := len(matches1) + L3a + L3b
	L2 := len(matches2)
	if L1 != L2 {
		return false, jsonString
	}

	return true, ""
}


func isIpCIDR(str string) (isIP, isCIDR bool, IP_out net.IP, IPNet_out net.IPNet) {

	_, IPNet_temp, error := net.ParseCIDR(str)
	if error == nil {
		isCIDR = true
		isIP = false
		IPNet_out = *IPNet_temp
	} else {
		//fmt.Println(error)
		IP2 := net.ParseIP(str)
		if IP2 != nil {
			isCIDR = false
			isIP = true
			IP_out = IP2
		}
	}
	//fmt.Println(IP_out,IPNet_out)
	return isIP, isCIDR, IP_out, IPNet_out
}

// ----------------------------------
// print rule


type RuleStrings struct {
	RuleSetId        string
	SenderString     string
	ReceiverString   string
	ProtocolString   string
	ResourceString   string
	OperationString  string
	ConditionsString string
	DecisionString   string
}

func GetRuleStrings(r *Rule) RuleStrings {
	output := RuleStrings{}

	output.SenderString = r.Sender.String()
	output.ReceiverString = r.Receiver.String()

	output.ProtocolString = "default"
	if r.Protocol != "" {
		output.ProtocolString = r.Protocol
	}

	output.ResourceString = r.Resource.String()

	output.OperationString = "default"
	if r.Operation != "" {
		output.OperationString = r.Operation
	}

	output.DecisionString = "default"
	if r.Decision != "" {
		output.DecisionString = r.Decision
	}

	output.ConditionsString = r.Conditions.ConditionsTree.String()

	return output
}




// Print displays one rule
func (r Rule) Print() {

	maplRuleStrings := GetRuleStrings(&r)

	fmt.Println("Sender (type:name):", maplRuleStrings.SenderString)
	fmt.Println("Receiver (type:name):", maplRuleStrings.ReceiverString)
	fmt.Println("Protocol:", maplRuleStrings.ProtocolString)
	fmt.Println("Resource (type:name):", maplRuleStrings.ResourceString)
	fmt.Println("Operation :", maplRuleStrings.OperationString)
	if maplRuleStrings.ConditionsString != "" {
		fmt.Println("Conditions :", maplRuleStrings.ConditionsString)
	}
	fmt.Println("Decision:", maplRuleStrings.DecisionString)
}
