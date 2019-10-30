package MAPL_engine

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// YamlReadRulesFromString function reads rules from a yaml string
func YamlReadRulesFromString(yamlString string) Rules {

	var rules Rules
	err := yaml.Unmarshal([]byte(yamlString), &rules)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	flag, outputString := IsNumberOfFieldsEqual(rules, yamlString)
	if flag == false {
		panic("number of fields in rules does not match number of fields in yaml file:\n" + outputString)
	}
	ConvertFieldsToRegexManyRules(&rules)
	//testFieldsForIP(&rules)
	ConvertConditionStringToIntFloatRegexManyRules(&rules)

	return rules
}

// JsonReadRulesFromString function reads rules from a json string
func JsonReadRulesFromString(jsonString string) Rules {

	var rules Rules
	err := json.Unmarshal([]byte(jsonString), &rules)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	ConvertFieldsToRegexManyRules(&rules)
	//testFieldsForIP(&rules)
	ConvertConditionStringToIntFloatRegexManyRules(&rules)

	return rules
}

// YamlReadRulesFromFile function reads rules from a file
func YamlReadRulesFromFile(filename string) Rules {

	filename = strings.Replace(filename, "\\", "/", -1)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	rules := YamlReadRulesFromString(string(data))
	return rules
}

//YamlReadOneRule function reads one rule from yaml string
func YamlReadOneRule(yamlString string) Rule {

	var rule Rule
	err := yaml.Unmarshal([]byte(yamlString), &rule)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	//fmt.Printf("---values found:\n%+v\n\n", rule)

	flag, outputString := IsNumberOfFieldsEqual(rule, yamlString)

	if flag == false {
		panic("number of fields in rule does not match number of fields in yaml file:\n" + outputString)
	}
	return rule
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

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc... for array of rules
func ConvertFieldsToRegexManyRules(rules *Rules) {
	// we replace wildcards with the corresponding regex

	for i, _ := range (rules.Rules) {
		ConvertFieldsToRegex(&rules.Rules[i])
	}
}

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc...
func ConvertFieldsToRegex(rule *Rule) {

	if rule.AlreadyConvertedFieldsToRegexFlag == true { // convert once
		return
	}

	rule.Sender.SenderList = ConvertStringToExpandedSenderReceiver(rule.Sender.SenderName, rule.Sender.SenderType)
	rule.Receiver.ReceiverList = ConvertStringToExpandedSenderReceiver(rule.Receiver.ReceiverName, rule.Receiver.ReceiverType)

	rule.OperationRegex = regexp.MustCompile(ConvertOperationStringToRegex(rule.Operation)).Copy() // a special case of regex for operations to support CRUD

	re := regexp.MustCompile(ConvertStringToRegex(rule.Resource.ResourceName))
	rule.Resource.ResourceNameRegex = re.Copy()

	rule.AlreadyConvertedFieldsToRegexFlag = true

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

func ConvertStringToExpandedSenderReceiver(str_in string, type_in string) []ExpandedSenderReceiver {
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
				panic("Type is 'subnet' but value is not an IP or CIDR")
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

		e.Regexp = regexp.MustCompile(str).Copy()

		output = append(output, e)
	}
	return output
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

// ConvertConditionStringToIntFloatRegexManyRules convert values in strings in the conditions to integers, floats and regex
// (or keep them default in case of failure) for array of rules
func ConvertConditionStringToIntFloatRegexManyRules(rules *Rules) {

	for i_rule, _ := range (rules.Rules) {
		ConvertConditionStringToIntFloatRegex(&rules.Rules[i_rule])
	}
}


func convertStringWithUnits(inputString string) (string, float64) {
	// see: https://en.wikipedia.org/wiki/Binary_prefix
	// also: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-memory

	factorVec := []float64{1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, math.Pow(1024,2),  math.Pow(1024,3),  math.Pow(1024,4),  math.Pow(1024,5),  math.Pow(1024,6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001}
	strVec := []string{"e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"}

	for i_unit, unit := range strVec {
		if strings.Contains(inputString, unit) {
			outputString := strings.Replace(inputString, unit, "", -1)
			factor := factorVec[i_unit]
			return outputString, factor
		}
	}
	return inputString, 1.0

}

// ConvertConditionStringToIntFloatRegexManyRules convert values in strings in the conditions to integers, floats and regex
// (or keep them default in case of failure)
func ConvertConditionStringToIntFloatRegex(r *Rule) {

	for i_dnf, andConditions := range (r.DNFConditions) {
		for i_and, condition := range (andConditions.ANDConditions) {

			if condition.Method == "IN" || condition.Method == "NIN"{
				L:=len(condition.Value)
				if L==-0{
					panic("test membership in empty array")
				}
				tempString:=strings.Replace(condition.Value,"[","",-1)
				tempString = strings.Replace(tempString,"]","",-1)
				tempString = strings.Replace(tempString,",","|",-1)

				if condition.Method == "IN"{
					r.DNFConditions[i_dnf].ANDConditions[i_and].Method="RE"
				}
				if condition.Method == "NIN"{
					r.DNFConditions[i_dnf].ANDConditions[i_and].Method="NRE"
				}
				r.DNFConditions[i_dnf].ANDConditions[i_and].Value = tempString
				condition.Value = tempString
			}


			tempString, factor := convertStringWithUnits(condition.Value)

			valFloat, err := strconv.ParseFloat(tempString, 64)
			valFloat = valFloat * factor
			if err == nil {
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueFloat = valFloat
			}
			valInt, err := strconv.ParseInt(condition.Value, 10, 64)
			if err == nil {
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueInt = valInt
			}
			re, err := regexp.Compile(condition.Value)
			if err == nil {
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueRegex = re.Copy() // this is used in RE,NRE
			}

			re, err = regexp.Compile(ConvertStringToRegex(condition.Value))
			if err == nil {
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueStringRegex = re.Copy() // this is used in EQ,NEQ
			} else {
				panic("condition.Value could not be converted to regex")
			}

			/*t, err := time.Parse(time.RFC3339,condition.Value)
			if err == nil{
				rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueTime = t
			}*/


			if strings.Index(condition.Attribute, "senderLabel[") == 0 { // test if ATTRIBUTE is of type senderLabel
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeIsSenderLabel = true
				i1 := strings.Index(condition.Attribute, "[") + 1
				i2 := strings.Index(condition.Attribute, "]")
				if i2 < len(condition.Attribute)-1 {
					panic("senderLabel has a wrong format")
				}
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeSenderLabelKey = condition.Attribute[i1:i2]
				r.DNFConditions[i_dnf].ANDConditions[i_and].Attribute = "senderLabel"
				r.DNFConditions[i_dnf].ANDConditions[i_and].OriginalAttribute = condition.Attribute // used in hash
			}
			if strings.Index(condition.Attribute, "receiverLabel[") == 0 { // test if ATTRIBUTE is of type receiverLabel
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeIsReceiverLabel = true
				i1 := strings.Index(condition.Attribute, "[") + 1
				i2 := strings.Index(condition.Attribute, "]")
				if i2 < len(condition.Attribute)-1 {
					panic("receiverLabel has a wrong format")
				}
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeReceiverLabelKey = condition.Attribute[i1:i2]
				r.DNFConditions[i_dnf].ANDConditions[i_and].Attribute = "receiverLabel"
				r.DNFConditions[i_dnf].ANDConditions[i_and].OriginalAttribute = condition.Attribute // used in hash
			}

			if strings.Index(condition.Value, "receiverLabel[") == 0 { // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueIsReceiverLabel = true
				i1 := strings.Index(condition.Value, "[") + 1
				i2 := strings.Index(condition.Value, "]")
				if i2 < len(condition.Value)-1 {
					panic("value receiverLabel has a wrong format")
				}
				r.DNFConditions[i_dnf].ANDConditions[i_and].ValueReceiverLabelKey = condition.Value[i1:i2]
				r.DNFConditions[i_dnf].ANDConditions[i_and].Value = "receiverLabel"
				r.DNFConditions[i_dnf].ANDConditions[i_and].OriginalValue = condition.Value // used in hash
			}

			if strings.Index(condition.Attribute, "jsonpath:") == 0 { // test if ATTRIBUTE is of type jsonpath
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeIsJsonpath = true
				i1 := strings.Index(condition.Attribute, ":") + 1
				i2 := len(condition.Attribute)
				netConditionAttribute := condition.Attribute[i1:i2]
				if netConditionAttribute[0] == '.' {
					netConditionAttribute = "$" + netConditionAttribute
				}
				netConditionAttribute = strings.Replace(netConditionAttribute, "\"", "'", -1)
				r.DNFConditions[i_dnf].ANDConditions[i_and].AttributeJsonpathQuery = netConditionAttribute
				r.DNFConditions[i_dnf].ANDConditions[i_and].Attribute = "jsonpath"
				r.DNFConditions[i_dnf].ANDConditions[i_and].OriginalAttribute = condition.Attribute // used in hash
			}
		}
	}
}

func PrepareRules(rules *Rules) {
	// prepare the rules for use (when loading from json not all the fields are ready...)
	ConvertFieldsToRegexManyRules(rules)                  // prepare the regex etc...
	ConvertConditionStringToIntFloatRegexManyRules(rules) // prepare the label conditions
}

func RuleConditionsToString(rule Rule) string {
	dnfStrings := []string{}
	for _, andConditions := range rule.DNFConditions {
		andStrings := []string{}
		for _, condition := range andConditions.ANDConditions {
			tempStr1 := condition.OriginalAttribute
			if len(tempStr1) == 0 {
				tempStr1 = condition.Attribute
			}
			tempStr2 := condition.OriginalValue
			if len(tempStr2) == 0 {
				tempStr2 = condition.Value
			}
			andStrings = append(andStrings, "<"+tempStr1+":"+condition.Method+":"+tempStr2+">")
		}
		sort.Strings(andStrings)
		andStr := ""
		for _, str := range (andStrings) {
			andStr += str + "&"
		}
		andStr = andStr[:len(andStr)-1]
		dnfStrings = append(dnfStrings, andStr)
	}
	sort.Strings(dnfStrings)
	totalDNFstring := "("
	for _, str := range (dnfStrings) {
		totalDNFstring += str + ")|("
	}
	if len(dnfStrings) > 0 {
		totalDNFstring = totalDNFstring[:len(totalDNFstring)-2]
	} else {
		totalDNFstring = "no conditions"
	}
	return totalDNFstring
}

func RuleToString(rule Rule) string {

	strMainPart := "<" + strings.ToLower(rule.Decision) + ">-<" + strings.ToLower(rule.Sender.SenderType) + ":" + rule.Sender.SenderName + ">-<" + strings.ToLower(rule.Receiver.ReceiverType) +
		":" + rule.Receiver.ReceiverName + ">-" + strings.ToLower(rule.Operation) + "-" + strings.ToLower(rule.Protocol) + "-<" + rule.Resource.ResourceType + "-" + rule.Resource.ResourceName + ">"

	totalDNFstring := RuleConditionsToString(rule)

	ruleStr := strMainPart + "-" + totalDNFstring
	return ruleStr
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

func (rule *Rule) ToLower() {
	rule.Sender.SenderType = strings.ToLower(rule.Sender.SenderType)
	rule.Receiver.ReceiverType = strings.ToLower(rule.Receiver.ReceiverType)
	rule.Resource.ResourceType = strings.ToLower(rule.Resource.ResourceType)
	rule.Protocol = strings.ToLower(rule.Protocol)
	rule.Operation = strings.ToLower(rule.Operation)
	rule.Decision = strings.ToLower(rule.Decision)
}
