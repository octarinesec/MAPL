package MAPL_engine

import (
	"gopkg.in/yaml.v2"
	"log"
	"regexp"
	"strings"
	"io/ioutil"
	"strconv"
)


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

func YamlReadRulesFromFile(filename string) Rules {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	rules := YamlReadRulesFromString(string(data))
	return rules
}



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

func convertStringToRegex(str string) string{
	str = strings.Replace(str,".","[.]",-1)
	str = strings.Replace(str,"*",".*",-1)
	str = strings.Replace(str,"?",".",-1)
	str = strings.Replace(str,"/","\\/",-1)
	str = "^"+str+"$" // force full string
	return str
}

func convertOperationStringToRegex(str string) string{

	switch(str){
	case "*":
		str=".*"
	case "write", "WRITE":
		str="(^POST$|^PUT$|^DELETE$)" // we cannot translate to ".*" because then rules of type "write:block" would apply to all messages.
	case "read", "READ":
		str="(^GET$|^HEAD$|^OPTIONS$|^TRACE$|^read$|^READ$)"
	}
	return str
}

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
