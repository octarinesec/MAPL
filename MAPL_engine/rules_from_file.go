package MAPL_engine

import (
	"gopkg.in/yaml.v2"
	"log"
	"regexp"
	"strings"
	"io/ioutil"
	"strconv"
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
	convertFieldsToRegex(&rules)
	rules = convertConditionStringToIntFloatRegex(rules)

	return rules
}

// YamlReadRulesFromFile function reads rules from a file
func YamlReadRulesFromFile(filename string) Rules {
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

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc...
func convertFieldsToRegex(rules *Rules) {
	// we replace wildcards with the corresponding regex

	for i, _ := range(rules.Rules) {

		rules.Rules[i].SenderRegex = regexp.MustCompile(convertStringToRegex(rules.Rules[i].Sender)).Copy()
		rules.Rules[i].ReceiverRegex = regexp.MustCompile(convertStringToRegex(rules.Rules[i].Receiver)).Copy()
		rules.Rules[i].OperationRegex = regexp.MustCompile(convertOperationStringToRegex(rules.Rules[i].Operation)).Copy() // a special case of regex for operations to support CRUD

		re := regexp.MustCompile(convertStringToRegex(rules.Rules[i].Resource.ResourceName))
		rules.Rules[i].Resource.ResourceNameRegex = re.Copy()

	}

}

// convertStringToRegex function converts one string to regex. Remove spaces, handle special characters and wildcards.
func convertStringToRegex(str_in string) string{

	str_list := strings.Split(str_in, ";")

	str_out:="("
	L := len(str_list)

	for i_str, str := range(str_list) {
		str = strings.Replace(str, " ", "", -1) // remove spaces
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
		str_out+=str
	}
	str_out += ")"
	return str_out
}

// convertOperationStringToRegex function converts the operations string to regex.
// this is a special case of convertStringToRegex
func convertOperationStringToRegex(str_in string) string{

	str_out:=""
	switch(str_in){
	case "*":
		str_out=".*"
	case "write", "WRITE":
		str_out="(^POST$|^PUT$|^DELETE$)" // we cannot translate to ".*" because then rules of type "write:block" would apply to all messages.
	case "read", "READ":
		str_out="(^GET$|^HEAD$|^OPTIONS$|^TRACE$|^read$|^READ$)"
	default:
		str_out=convertStringToRegex(str_in)
	}
	return str_out
}

// convertConditionStringToIntFloatRegex convert values in strings in the conditions to integers, floats and regex
// (or keep them default in case of failure)
func convertConditionStringToIntFloatRegex(rules_in Rules) Rules {
	rules_out := rules_in

	for i_rule, r := range(rules_out.Rules) {
		for i_dnf, andConditions:=range(r.DNFConditions) {
			for i_and, condition := range (andConditions.ANDConditions) {
				valFloat, err := strconv.ParseFloat(condition.Value, 64)
				if err == nil {
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueFloat = valFloat
				}
				valInt, err := strconv.ParseInt(condition.Value, 10, 64)
				if err == nil {
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueInt = valInt
				}
				re, err := regexp.Compile(condition.Value)
				if err == nil {
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueRegex = re.Copy()
				}
				/*t, err := time.Parse(time.RFC3339,condition.Value)
				if err == nil{
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueTime = t
				}*/
			}
		}
	}

	return rules_out
}
