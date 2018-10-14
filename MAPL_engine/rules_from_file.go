package MAPL_engine

import (
	"gopkg.in/yaml.v2"
	"log"
	"regexp"
	"strings"
	"io/ioutil"
	"strconv"
	"net"
	"crypto/md5"
	"fmt"
	"sort"
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
	ConvertFieldsToRegex(&rules)
	//testFieldsForIP(&rules)
	rules = ConvertConditionStringToIntFloatRegex(rules)

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

func isIpCIDR(str string) (isIP,isCIDR bool,IP_out net.IP,IPNet_out net.IPNet) {

	_, IPNet_temp, error := net.ParseCIDR(str)
	if error==nil{
		isCIDR=true
		isIP=false
		IPNet_out = *IPNet_temp
	}else {
		//fmt.Println(error)
		IP2 := net.ParseIP(str)
		if IP2 != nil {
			isCIDR = false
			isIP = true
			IP_out = IP2
		}
	}
	//fmt.Println(IP_out,IPNet_out)
	return isIP,isCIDR,IP_out,IPNet_out
}

// convertFieldsToRegex converts some rule fields into regular expressions to be used later.
// This enables use of wildcards in the sender, receiver names, etc...
func ConvertFieldsToRegex(rules *Rules) {
	// we replace wildcards with the corresponding regex

	for i, _ := range(rules.Rules) {

		rules.Rules[i].SenderList = ConvertStringToExpandedSenderReceiver(rules.Rules[i].Sender)
		rules.Rules[i].ReceiverList = ConvertStringToExpandedSenderReceiver(rules.Rules[i].Receiver)

		rules.Rules[i].OperationRegex = regexp.MustCompile(ConvertOperationStringToRegex(rules.Rules[i].Operation)).Copy() // a special case of regex for operations to support CRUD

		re := regexp.MustCompile(ConvertStringToRegex(rules.Rules[i].Resource.ResourceName))
		rules.Rules[i].Resource.ResourceNameRegex = re.Copy()

	}
 	//fmt.Printf("%+v\n",rules)
	//fmt.Println("-------------")
}

// convertStringToRegex function converts one string to regex. Remove spaces, handle special characters and wildcards.
func ConvertStringToRegex(str_in string) string{

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

func ConvertStringToExpandedSenderReceiver(str_in string) []ExpandedSenderReceiver{
	var output []ExpandedSenderReceiver

	str_list := strings.Split(str_in, ";")
	for _, str := range(str_list) {
		var e ExpandedSenderReceiver
		e.Name=str
		e.IsIP,e.IsCIDR,e.IP,e.CIDR=isIpCIDR(str)

		str = strings.Replace(str, " ", "", -1)    // remove spaces
		str = strings.Replace(str, ".", "[.]", -1) // handle dot for conversion to regex
		str = strings.Replace(str, "$", "\\$", -1)
		str = strings.Replace(str, "^", "\\^", -1)
		str = strings.Replace(str, "*", ".*", -1)
		str = strings.Replace(str, "?", ".", -1)
		str = strings.Replace(str, "/", "\\/", -1)
		str = "^" + str + "$" // force full string

		e.Regexp=regexp.MustCompile(str).Copy()

		output=append(output,e)
	}
	return output
}


// convertOperationStringToRegex function converts the operations string to regex.
// this is a special case of convertStringToRegex
func ConvertOperationStringToRegex(str_in string) string{

	str_out:=""
	switch(str_in){
	case "*":
		str_out=".*"
	case "write", "WRITE":
		str_out="(^POST$|^PUT$|^DELETE$)" // we cannot translate to ".*" because then rules of type "write:block" would apply to all messages.
	case "read", "READ":
		str_out="(^GET$|^HEAD$|^OPTIONS$|^TRACE$|^read$|^READ$)"
	default:
		str_out=ConvertStringToRegex(str_in)
	}
	return str_out
}

// convertConditionStringToIntFloatRegex convert values in strings in the conditions to integers, floats and regex
// (or keep them default in case of failure)
func ConvertConditionStringToIntFloatRegex(rules_in Rules) Rules {
	rules_out := rules_in

	for i_rule, r := range(rules_out.Rules) {
		for i_dnf, andConditions:=range(r.DNFConditions) {
			for i_and, condition := range (andConditions.ANDConditions) {

				rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].OriginalAttribute=condition.Attribute // used in hash
				rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].OriginalValue=condition.Value // used in hash

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
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueRegex = re.Copy()  // this is used in RE,NRE
				}

				re,err = regexp.Compile(ConvertStringToRegex(condition.Value))
				if err == nil{
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueStringRegex = re.Copy() // this is used in EQ,NEQ
				}else{
					panic("condition.Value could not be converted to regex")
				}

				/*t, err := time.Parse(time.RFC3339,condition.Value)
				if err == nil{
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueTime = t
				}*/

				if strings.Index(condition.Attribute,"senderLabel[")==0{ // test if ATTRIBUTE is of type senderLabel
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].AttributeIsSenderLabel=true
					i1:=strings.Index(condition.Attribute,"[")+1
					i2:=strings.Index(condition.Attribute,"]")
					if i2 < len(condition.Attribute)-1{
						panic("senderLabel has a wrong format")
					}
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].AttributeSenderLabelKey=condition.Attribute[i1:i2]
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].Attribute="senderLabel"
				}
				if strings.Index(condition.Attribute,"receiverLabel[")==0{ // test if ATTRIBUTE is of type receiverLabel
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].AttributeIsReceiverLabel=true
					i1:=strings.Index(condition.Attribute,"[")+1
					i2:=strings.Index(condition.Attribute,"]")
					if i2 < len(condition.Attribute)-1{
						panic("receiverLabel has a wrong format")
					}
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].AttributeReceiverLabelKey=condition.Attribute[i1:i2]
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].Attribute="receiverLabel"
				}

				if strings.Index(condition.Value,"receiverLabel[")==0{ // test if VALUE is of type receiverLabel (used to compare attribute senderLabel[key1] to value receiverLabel[key2])
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueIsReceiverLabel=true
					i1:=strings.Index(condition.Value,"[")+1
					i2:=strings.Index(condition.Value,"]")
					if i2 < len(condition.Value)-1{
						panic("value receiverLabel has a wrong format")
					}
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].ValueReceiverLabelKey=condition.Value[i1:i2]
					rules_out.Rules[i_rule].DNFConditions[i_dnf].ANDConditions[i_and].Value="receiverLabel"
				}

			}




		}
	}

	return rules_out
}

func RuleMD5Hash(rule Rule) (md5hash string){
	strMainPart := rule.Decision+"-"+rule.Sender+"-"+rule.Receiver+"-"+rule.Operation+"-["+rule.Resource.ResourceProtocol+"-"+rule.Resource.ResourceType+"-"+rule.Resource.ResourceName+"]"

	dnfStrings:= []string{}
	for _, andConditions := range rule.DNFConditions{
		andStrings := []string{}
		for _,condition := range andConditions.ANDConditions{
			andStrings=append(andStrings,"<"+condition.OriginalAttribute+":"+condition.Method+":"+condition.OriginalValue+">")
		}
		sort.Strings(andStrings)
		andStr:=""
		for _, str:=range(andStrings){
			andStr+=str+"&"
		}
		andStr=andStr[:len(andStr)-1]
		dnfStrings=append(dnfStrings,andStr)
	}
	sort.Strings(dnfStrings)
	totalDNFstring:="("
	for _, str:=range(dnfStrings){
		totalDNFstring+=str+")|("
	}
	totalDNFstring=totalDNFstring[:len(totalDNFstring)-2]

	ruleStr:=strMainPart+"-"+totalDNFstring

	data := []byte(ruleStr)
	//md5hash = fmt.Sprintf("%x", md5.Sum(data))
	md5hash = fmt.Sprintf("%x", md5.Sum(data))

	return md5hash
}