package MAPL_engine

import (
	"fmt"
	"regexp"
	"strings"
)

// IsNumberOfFieldsEqual is used to compare the structures read from files (mostly while debugging).
// We convert the structure into a string and count the number of non-empty "fields". Then we compare to the number of non empty fields in the original yaml string.
// It will not work with structure fields with default values (for example ints or floats) so we remove them.
func IsNumberOfFieldsEqual(generalStruct GeneralStruct, yamlString string) (bool, string) {
	return compareJsonAndYaml(generalStruct.ToJson(), yamlString)
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

	//re := regexp.MustCompile("[[:alnum:]][:][ ][[:alnum:]]") // catches fieldnam[e: v]alue'
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
