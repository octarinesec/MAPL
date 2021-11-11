package MAPL_engine

import (
	"errors"
	"fmt"
	"strings"
)

func convertAttributesWithArraysToANYNode(jsonStr string) (string, error) {
	jsonStr0 := jsonStr
	exitLoop:=false
	err:=errors.New("error")
	for true {
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

	jsonStrOut := ""
	exitLoop := true
	for true {

		ind := strings.Index(jsonStr, `"attribute"`)
		if ind == -1 {
			jsonStrOut += jsonStr
			return jsonStrOut, exitLoop, nil
		}

		jsonStrOut += jsonStr[0:ind]

		tempStr := jsonStr[ind:]
		ind = strings.Index(tempStr, `"jsonpath:`)
		if ind == -1 {
			return "", true, fmt.Errorf("no jsonpath in attribute")
		}
		tempStr2 := tempStr[ind+1:]
		ind = strings.Index(tempStr2, `"`)

		attribute := tempStr2[0:ind]
		indStart, indEnd := isArrayAttribute(attribute)
		newStr := ""
		insertBracketFlag := false
		if indStart == -1 { // attribute is not an array
			newStr = fmt.Sprintf(`"attribute":"%v"`, attribute)
			insertBracketFlag = false
		} else {
			exitLoop = false
			startOfArray := attribute[0:indEnd]
			endOfArray := attribute[indEnd:]

			newStr = fmt.Sprintf(`"ANY":{"parentJsonpathAttribute":"%v","condition":{"attribute":"jsonpath:$RELATIVE%v"`, startOfArray, endOfArray)
			insertBracketFlag = true
		}

		jsonStrOut += newStr

		ind = strings.Index(tempStr2, attribute) + len(attribute) + 1
		jsonStr = tempStr2[ind:]

		if insertBracketFlag {
			jsonStr = insertTwoBrackets(jsonStr)
		}

	}
	return jsonStrOut, true, nil

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
