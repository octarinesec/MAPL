package MAPL_engine

import (
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
)

func RemoveDotQuotes(str string) string {
	flagRemoveQuote := false
	flagRemoveDoubleQuote := false
	strOut := ""
	chPrev := '!'
	for _, ch := range str {
		if chPrev == '.' {
			if ch == '\'' {
				flagRemoveQuote = true
				chPrev = ch
				continue
			}
			if ch == '"' {
				flagRemoveDoubleQuote = true
				chPrev = ch
				continue
			}
		}
		if flagRemoveQuote && ch == '\'' {
			flagRemoveQuote = false
			chPrev = ch
			continue
		}
		if flagRemoveDoubleQuote && ch == '"' {
			flagRemoveDoubleQuote = false
			chPrev = ch
			continue
		}
		strOut = strOut + string(ch)
		chPrev = ch
	}
	return strOut
}

// convertStringToRegex function converts one string to regex. Remove spaces, handle special characters and wildcards.
func ConvertStringToRegex(str_in, method string) string {

	str_out := "^" + str_in + "$"

	if method == "IN" || method == "NIN" || method == "WithWildcards" { // We try to convert to a list only in case of IN or NIN
		str_list := strings.Split(str_in, ",")

		str_out = "("
		L := len(str_list)

		for i_str, str := range str_list {
			str = strings.TrimSpace(str)               // remove leading and trailing spaces
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
	}
	return str_out
}

func ConvertStringToExpandedSenderReceiver(str_in string, type_in string) ([]ExpandedSenderReceiver, error) {
	var output []ExpandedSenderReceiver

	str_list := strings.Split(str_in, ",")
	for _, str := range str_list {
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
				return []ExpandedSenderReceiver{}, fmt.Errorf("Type is 'subnet' but value is not an IP or CIDR")
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

		re, err := regexp.Compile(str)
		if err != nil {
			return []ExpandedSenderReceiver{}, fmt.Errorf("can't create regex of value in list: %v", err)
		}
		e.Regexp = re.Copy()
		output = append(output, e)
	}
	return output, nil
}

// convertOperationStringToRegex function converts the operations string to regex.
// this is a special case of convertStringToRegex
func ConvertOperationStringToRegex(str_in string) string {

	str_out := ""
	switch str_in {
	case "*":
		str_out = ".*"
	case "write", "WRITE":
		str_out = "(^POST$|^PUT$|^DELETE$)" // we cannot translate to ".*" because then rules of type "write:block" would apply to all messages.
	case "read", "READ":
		str_out = "(^GET$|^HEAD$|^OPTIONS$|^TRACE$|^read$|^READ$)"
	default:
		str_out = ConvertStringToRegex(str_in, "WithWildcards") // we allow automatic use of wildcards in Operation attribute
	}
	return str_out
}

func SliceHasPrefix(sl []string, v string) bool {
	for _, vv := range sl {
		if strings.HasPrefix(v, vv) {
			return true
		}
	}
	return false
}

func convertStringWithUnits(inputString string) (string, float64) {
	// see: https://en.wikipedia.org/wiki/Binary_prefix
	// also: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/#meaning-of-memory

	factorVec := []float64{1e-2, 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, math.Pow(1024, 2), math.Pow(1024, 3), math.Pow(1024, 4), math.Pow(1024, 5), math.Pow(1024, 6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001}
	strVec := []string{"%", "e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"}

	for i_unit, unit := range strVec {

		flag1 := strings.HasSuffix(inputString, unit)
		flag2 := strings.Count(inputString, unit) == 1

		if flag1 && flag2 {
			outputString := strings.Replace(inputString, unit, "", -1)
			factor := factorVec[i_unit]
			return outputString, factor
		}
	}
	return inputString, 1.0

}

func removeQuotesAndBrackets(valueToCompareString string) string {
	valueToCompareString = strings.Replace(valueToCompareString, "[[", "[", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "]]", "]", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "[\"", "\"", -1)
	valueToCompareString = strings.Replace(valueToCompareString, "\"]", "\"", -1)
	if valueToCompareString == "[]" {
		valueToCompareString = ""
	}
	if len(valueToCompareString) >= 2 {
		if valueToCompareString[0] == '"' && valueToCompareString[len(valueToCompareString)-1] == '"' {
			valueToCompareString = valueToCompareString[1 : len(valueToCompareString)-1]
		}
	}
	return valueToCompareString
}

func removeQuotesFromResult(str string) (string, bool) {

	L := len(str) - 1
	if L > 0 {
		if (str[0] == '"' && str[L] != '"') || (str[L] == '"' && str[0] != '"') {
			log.Printf("quotation marks not aligned (1): str=%v", str)
			return "", false
		}

		if str[L] == '"' && str[0] == '"' {
			str = str[1:L]
		}
	}
	return str, true
}
