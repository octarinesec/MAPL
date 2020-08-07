package MAPL_engine

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"strings"
)

// YamlReadMessagesFromString function reads messages from a yaml string
func YamlReadStringListsFromString(yamlString string) (PredefinedStringsAndLists, error) {

	var predefinedStringsAndLists PredefinedStringsAndLists
	err := yaml.Unmarshal([]byte(yamlString), &predefinedStringsAndLists)
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}

	predefinedStringsAndLists, err = validatePredefinedString(predefinedStringsAndLists)
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}

	return predefinedStringsAndLists, nil
}

func YamlReadStringListsFromFile(filename string) (PredefinedStringsAndLists, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}
	predefinedStringsAndLists, err := YamlReadStringListsFromString(string(data))
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}
	return predefinedStringsAndLists, nil
}

func validatePredefinedString(predefinedStringsAndLists PredefinedStringsAndLists) (PredefinedStringsAndLists, error) {

	predefinedStringsAndLists.PredefinedListsWithoutRefs = map[string][]string{} // initialize
	for key := range predefinedStringsAndLists.PredefinedLists {

		stringArray := predefinedStringsAndLists.PredefinedLists[key]
		tempStringArray := []string{}

		for _, str := range (stringArray) {
			if strings.HasPrefix(str, "#") { // this is a reference
				key2 := strings.Replace(str, "#", "", 1)
				strTemp, ok := predefinedStringsAndLists.PredefinedStrings[key2]
				if !ok {
					return PredefinedStringsAndLists{}, fmt.Errorf("missing predefined strings [%v]", str)
				}
				tempStringArray = append(tempStringArray, strTemp)
			} else {
				tempStringArray = append(tempStringArray, str)
			}
		}

		predefinedStringsAndLists.PredefinedListsWithoutRefs[key] = tempStringArray

	}
	return predefinedStringsAndLists, nil
}
