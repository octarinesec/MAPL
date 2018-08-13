package main

import (
	"fmt"
	"os"
	"log"
	"io/ioutil"

	"github.com/octarinesec/MAPL/MAPL_engine"

)

func main() {

	logging := false
	if logging{
		// setup a log outfile file
		f, err := os.OpenFile("log.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777) //create your file with desired read/write permissions
		if err != nil {
			log.Fatal(err)
		}
		defer f.Sync()
		defer f.Close()
		log.SetOutput(f) //set output of logs to f
	}else{
		log.SetOutput(ioutil.Discard) // when we complete the debugging we discard the logs [output discarded]
	}

	// test whitelist: sender. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry), message 2: block by default (no relevant whitelist entry)  message 3: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_basic.yaml","examples/messages_basic_sender_name.yaml")
	fmt.Println("----------------------")

	// test whitelist: receiver. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_basic.yaml","examples/messages_basic_receiver_name.yaml")
	fmt.Println("----------------------")

	// test whitelist: sender with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_sender_with_wildcards.yaml","examples/messages_sender_name_test_with_wildcards.yaml")
	fmt.Println("----------------------")

	// test whitelist: receiver with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_receiver_with_wildcards.yaml","examples/messages_receiver_name_test_with_wildcards.yaml")
	fmt.Println("----------------------")

	// test whitelist: sender lists. Expected results: messages 0,1: allow, messages 2: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_sender_list.yaml","examples/messages_sender_test_with_lists.yaml")
	fmt.Println("----------------------")

	// test whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block , message 2: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_resources.yaml","examples/messages_resources.yaml")
	fmt.Println("----------------------")

	// test whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block
	Test_CheckMessages("examples/rules_resources_with_wildcards.yaml","examples/messages_resources_test_with_wildcards.yaml")
	fmt.Println("----------------------")

	// test whitelist: resources with lists. Expected results: messages 0,1: alert, message 2: block
	Test_CheckMessages("examples/rules_resource_lists.yaml","examples/messages_resources_test_with_lists.yaml")
	fmt.Println("----------------------")

	// test whitelist: operations. Expected results: messages 0: allow, messages 1: block , message 2: block by default (no relevant whitelist entry), message 3: allow, message 4: block , message 5: block
	Test_CheckMessages("examples/rules_operations.yaml","examples/messages_operations.yaml")
	fmt.Println("----------------------")

	// test whitelist: operations with lists. Expected results: messages 1,2: allow, messages 0,3: block by default (no relevant whitelist entry)
	Test_CheckMessages("examples/rules_operation_list.yaml","examples/messages_operations_test_with_list.yaml")
	fmt.Println("----------------------")

	// test whitelist: conditions. Expected results:
	// messages 0: allow by rule 0 (allows everything)
	// messages 1: block by condition on payloadSize
	// messages 2: block by condition on payloadSize
	// messages 3: allow by rule 0 (allows everything)
	// messages 4: block by condition on utcHoursFromMidnight
	// messages 5: block by condition on payloadSize and utcHoursFromMidnight
	Test_CheckMessages("examples/rules_with_conditions.yaml","examples/messages_test_with_conditions.yaml")
	fmt.Println("----------------------")


	//-------------------------------------------------------------------------------------------------------------------------------------------------
	// test rules for istio's bookinfo app
	Test_CheckMessages("examples/rules_istio.yaml","examples/messages_istio.yaml")
	fmt.Println("----------------------")


}

func Test_CheckMessages(rulesFilename string,messagesFilename string) {

	var rules= MAPL_engine.YamlReadRulesFromFile(rulesFilename)
	var messages = MAPL_engine.YamlReadMessagesFromFile(messagesFilename)

	for i_message, message := range(messages.Messages) {

		result, msg, relevantRuleIndex, _ , appliedRulesIndices := MAPL_engine.Check(&message, &rules)
		if relevantRuleIndex>=0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID,appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}

	}
}

