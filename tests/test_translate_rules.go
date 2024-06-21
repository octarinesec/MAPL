package main

import (
	"fmt"
	"github.com/octarinesec/MAPL/MAPL_engine"
	"github.com/octarinesec/MAPL/extras"
)

// The main test calls extras.RemoveLabelConditionsFromRules with the rule structure.
func main() {

	service_labels := make(map[string]map[string]string)

	service_labels["serviceA"]=map[string]string{"key1":"a", "key2":"b", "key3":"c", "key4":"d", "key5":"e","can-access-serviceX":"true"}
	service_labels["serviceB"]=map[string]string{"key1":"a", "key2":"b", "key3":"c", "key4":"d"}
	service_labels["serviceC"]=map[string]string{"key1":"A", "key2":"B", "key3":"C"}
	service_labels["serviceD"]=map[string]string{"key1":"A", "key2":"B","can-access-serviceX":"true"}
	service_labels["serviceE"]=map[string]string{"key1":"abc", "key2":"def","can-access-serviceY":"true"}
	service_labels["serviceX"]=map[string]string{}
	service_labels["serviceY"]=map[string]string{}

	rulesFilename := "examples/rules_for_testing_rule_translation.yaml"
	var rules= MAPL_engine.YamlReadRulesFromFile(rulesFilename)

	/*messagesFilename := "examples/messages_for_rule_translation.yaml"
	var messages = MAPL_engine.YamlReadMessagesFromFile(messagesFilename)
	message_attributes := messages.Messages[0]
	*/
	service_labels_explicit:=map[string]map[string]string{}
	err:=extras.RemoveLabelConditionsFromRules(&rules,service_labels,service_labels_explicit)
	fmt.Println(err)
	filename := "outputs/translated_rules.yaml"
	extras.OutputRulesToFile(&rules,filename)
}
