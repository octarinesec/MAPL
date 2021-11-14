package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Some conversions that help trasnform MAPL v1 rules to MAPL v2
func convertAttributesWithArraysToANYNode(jsonStr0 string) (string, error) {
	// --- condense ---
	var aux interface{}
	if err := json.Unmarshal([]byte(jsonStr0), &aux); err != nil {
		return "", err
	}
	jsonBytes, err := json.Marshal(aux)
	if err != nil {
		return "", err
	}
	jsonStr := string(jsonBytes)
	// ----------------
	exitLoop := false
	for true { // in each loop we convert one level attribute with array [so that an attribute with tow levels of arrays requires two loops]
		jsonStr, exitLoop, err = convertAttributesWithArraysToANYNodeInner(jsonStr)
		if err != nil {
			return jsonStr0, err
		}
		if exitLoop {
			break
		}
	}
	return jsonStr, nil
}

func convertAttributesWithArraysToANYNodeInner(jsonStr string) (string, bool, error) {
	// it is assumed that the attribute key word is the FIRST in the "condition" node
	// we build a new json string from the old one where we convert attribute with array
	// to "ANY" node json string
	jsonStrOut := ""
	exitLoop := true
	for true { // we go over all of the attributes

		ind := strings.Index(jsonStr, `"attribute"`) // we find the next "attribute"
		if ind == -1 {
			jsonStrOut += jsonStr
			return jsonStrOut, exitLoop, nil
		}

		jsonStrOut += jsonStr[0:ind]

		tempStr := jsonStr[ind:]
		ind = strings.Index(tempStr, `":"`)
		ind = ind + 3
		tempStr2 := tempStr[ind:]

		ind = strings.Index(tempStr2, `"`)
		attribute := tempStr2[0:ind] // this is the attribute string

		ind = strings.Index(tempStr2, attribute) + len(attribute) + 1
		tempStr3 := tempStr2[ind:]

		ind = strings.Index(tempStr3, `"value":`)
		var tempStr4 string
		var tempStr5 string
		if ind != -1 {
			tempStr4 = tempStr3[:ind]
			tempStr5 = tempStr3[ind:]
		} else {
			tempStr4 = ""
			tempStr5 = tempStr3
		}

		ind = strings.Index(tempStr5, `}`)
		conditionEnd := tempStr4 + tempStr5[:ind]

		jsonStr = tempStr5[ind:]

		indStart, indEnd := isArrayAttribute(attribute)
		newStr := ""
		insertBracketFlag := false
		insertSquareBracketFlag := false
		if indStart == -1 { // attribute is not an array
			newStr = fmt.Sprintf(`"attribute":"%v"%v`, attribute, conditionEnd)
			insertBracketFlag = false
		} else { // attribute contains an array
			exitLoop = false
			startOfArray := attribute[0:indEnd] // this is the first array of the attribute
			endOfArray := attribute[indEnd:]
			// we convert to "ANY" node:
			newStr, insertSquareBracketFlag = getAnyNode(startOfArray, endOfArray, conditionEnd)

			insertBracketFlag = true
		}

		jsonStrOut += newStr

		if insertSquareBracketFlag {
			//	jsonStr = insertSquareBracket(jsonStr) // after converting to ANY node we need to close the temporary string with two right brackets "}}" [since the ANY nodes adds left brackets]
		}

		if insertBracketFlag {
		//	jsonStr = insertTwoBrackets(jsonStr) // after converting to ANY node we need to close the temporary string with two right brackets "}}" [since the ANY nodes adds left brackets]
		}

	}
	return jsonStrOut, true, nil

}

func getAnyNode(startOfArray, endOfArray, conditionEnd string) (string, bool) {

	newStr := fmt.Sprintf(`"ANY":{"parentJsonpathAttribute":"%v","condition":{"attribute":"jsonpath:$RELATIVE%v"%v}}`, startOfArray, endOfArray, conditionEnd)

	filterArrayFlag := strings.Contains(startOfArray, "[?(@.")
	if !filterArrayFlag {
		return newStr, false
	}

	ind1 := strings.Index(startOfArray, "[")
	ind2 := strings.Index(startOfArray, "]")

	filter := startOfArray[ind1+1 : ind2]
	startOfArray = startOfArray[:ind1]

	if !strings.Contains(filter, "==") {
		return newStr, false
	}
	ind3 := strings.Index(filter, "?(@.")
	ind4 := strings.Index(filter, "==")
	ind5 := strings.Index(filter, ")")
	filterName := filter[ind3+3 : ind4]
	filterValue := filter[ind4+2 : ind5]
	filterValue, _ = removeQuotes(filterValue)

	cond1 := fmt.Sprintf(`"attribute":"jsonpath:$RELATIVE%v","method":"EQ","value":"%v"`, filterName, filterValue)
	cond2 := fmt.Sprintf(`"attribute":"jsonpath:$RELATIVE%v"%v`, endOfArray,conditionEnd)
	andCondition := fmt.Sprintf(`"AND":[{"condition":{%v}},{"condition":{%v}}]`, cond1, cond2)
	newStr = fmt.Sprintf(`"ANY":{"parentJsonpathAttribute":"%v[*]","condition":{%v}}`, startOfArray, andCondition)

	return newStr, true
}

func insertTwoBrackets(str string) string {
	leftCounter := 0
	for i, c := range str {
		if c == '{' {
			leftCounter++
		}
		if c == '}' {
			if leftCounter == 0 {
				strOut := str[:i] + "}}" + str[i:]
				return strOut
			} else {
				leftCounter--
			}
		}
	}
	return str + "}}"

}

func insertSquareBracket(str string) string {
	leftCounter := 0
	for i, c := range str {
		if c == '[' {
			leftCounter++
		}
		if c == ']' {
			if leftCounter == 0 {
				strOut := str[:i] + "]" + str[i:]
				return strOut
			} else {
				leftCounter--
			}
		}
	}
	return str + "]"

}
func isArrayAttribute(attribute string) (int, int) {
	ind1a, ind1b := arrayInAttribute(attribute, "[:]")
	ind2a, ind2b := arrayInAttribute(attribute, "[*]")
	ind3a, ind3b := arrayInAttribute(attribute, "[?")

	ind0 := 1000000
	indStart := ind0
	indEnd := ind0
	if ind1a >= 0 && ind1b >= 0 && ind1a < indStart {
		indStart = ind1a
		indEnd = ind1b + 1
	}
	if ind2a >= 0 && ind2b >= 0 && ind2a < indStart {
		indStart = ind2a
		indEnd = ind2b + 1
	}
	if ind3a >= 0 && ind3b >= 0 && ind3a < indStart {
		indStart = ind3a
		indEnd = ind3b + 1
	}
	if indStart == ind0 || indEnd == ind0 {
		return -1, -1
	}
	return indStart, indEnd
}

func arrayInAttribute(attribute, arr string) (int, int) {

	ind1 := strings.Index(attribute, arr)
	if ind1 == -1 {
		return -1, -1
	}
	attribute2 := attribute[ind1:]
	ind2 := strings.Index(attribute2, "]")
	if ind2 == -1 {
		return -1, -1
	}
	return ind1, ind1 + ind2
}
