package MAPL_engine

import (
	"fmt"
	"os"
	"log"
	"io/ioutil"
	"testing"
	"github.com/smartystreets/goconvey/convey/reporting"
	. "github.com/smartystreets/goconvey/convey"
	"bufio"
)

// The main test calls Test_CheckMessages with different sets of rule and message yaml files as inputs. The rule and message yaml files are stored in the examples folder.
func TestMaplEngine(t *testing.T) {

	logging := false
	if logging {
		// setup a log outfile file
		f, err := os.OpenFile("log.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777) //create your file with desired read/write permissions
		if err != nil {
			log.Fatal(err)
		}
		defer f.Sync()
		defer f.Close()
		log.SetOutput(f) //set output of logs to f
	} else {
		log.SetOutput(ioutil.Discard) // when we complete the debugging we discard the logs [output discarded]
	}

	reporting.QuietMode()
	Convey("tests", t, func() {

		str := "test hash function. expected result: although the conditions are ordered differently, rule 0 and rule 1 should have the same hash\n and also rule 2 and rule 4"
		fmt.Println(str)
		hashes := test_MD5Hash("../examples/rules_with_label_conditions_for_hash_tests.yaml")
		So(hashes[0], ShouldEqual, hashes[1])
		So(hashes[2], ShouldEqual, hashes[4])
		So(hashes[3], ShouldNotEqual, hashes[0])
		So(hashes[3], ShouldNotEqual, hashes[2])
		So(hashes[5], ShouldNotEqual, hashes[0])
		So(hashes[5], ShouldNotEqual, hashes[2])
		fmt.Println("----------------------")

		str = "test whitelist: sender. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry), message 2: block by default (no relevant whitelist entry)  message 3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results := test_CheckMessages("../examples/rules_basic.yaml", "../examples/messages_basic_sender_name.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: receiver. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_basic.yaml", "../examples/messages_basic_receiver_name.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_sender_with_wildcards.yaml", "../examples/messages_sender_name_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: receiver with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_receiver_with_wildcards.yaml", "../examples/messages_receiver_name_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender lists. Expected results: messages 0,1: allow, messages 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_sender_list.yaml", "../examples/messages_sender_test_with_lists.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender ip. Expected results: message 0,1,3,4: allow, message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_sender_ips.yaml", "../examples/messages_basic_sender_ip.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: receiver ip. message 2: allow, messages 0,1: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_receiver_ips.yaml", "../examples/messages_basic_receiver_ip.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "est whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block , message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_resources.yaml", "../examples/messages_resources.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_resources_with_wildcards.yaml", "../examples/messages_resources_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		fmt.Println("----------------------")

		str = "test whitelist: resources with lists. Expected results: messages 0,1: alert, message 2: block"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_resource_lists.yaml", "../examples/messages_resources_test_with_lists.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, ALERT)
		So(results[2], ShouldEqual, BLOCK)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		So(results[5], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: operations. Expected results: messages 0: allow, messages 1: block , message 2: block by default (no relevant whitelist entry), message 3: allow, message 4: block , message 5: block"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_operations.yaml", "../examples/messages_operations.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: operations with lists. Expected results: messages 1,2: allow, messages 0,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_operation_list.yaml", "../examples/messages_operations_test_with_list.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		// test whitelist: conditions. Expected results:
		// messages 0: allow by rule 0 (allows everything)
		// messages 1: block by condition on payloadSize
		// messages 2: block by condition on payloadSize
		// messages 3: allow by rule 0 (allows everything)
		// messages 4: block by condition on utcHoursFromMidnight
		// messages 5: block by condition on payloadSize and utcHoursFromMidnight
		str = "test whitelist: conditions. 0,3: allow, 1,2,4,5: block by conditions"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_conditions.yaml", "../examples/messages_test_with_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, BLOCK)
		So(results[3], ShouldEqual, ALLOW)
		So(results[4], ShouldEqual, BLOCK)
		So(results[5], ShouldEqual, BLOCK)
		fmt.Println("----------------------")

		str = "test whitelist: conditions with sender and receiver labels"
		// Expected results:
		// message 0: allow by rule 0
		// message 1: allow by rule 0
		// message 2: allow by rule 1
		// message 3: allow by rule 2
		// message 4: block by default
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_label_conditions.yaml", "../examples/messages_test_with_label_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, ALLOW)
		So(results[4], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		// test whitelist: conditions on encryption. Expected results:
		// messages 0: block by default
		// messages 1: block by default
		// messages 2: allow by condition on encryption

		str = "test encryption conditions: 0,1: block by default, 2: allow by conditions on encryption"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_encryption_conditions.yaml", "../examples/messages_test_with_encryption_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")


		str = "test EX and NEX methods"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_EX_conditions.yaml", "../examples/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		results = test_CheckMessages("../examples/rules_with_NEX_conditions.yaml", "../examples/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")


		str = "test IN and NIN methods"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_with_IN_conditions.yaml", "../examples/messages_test_with_IN_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		results = test_CheckMessages("../examples/rules_with_NIN_conditions.yaml", "../examples/messages_test_with_IN_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")


		str = "test jsonpath conditions"
		fmt.Println(str)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_GT.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_GT.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data2.json")
		So(results[0], ShouldEqual, BLOCK)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_EQ.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_foo.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_foofoo.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, ALLOW)

		// EX:
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists0.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists1.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, ALLOW)

		// NEX:
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists0b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists1b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_label_key_exists2b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, DEFAULT)


		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_annotations_EQ.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data3.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_template_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		fmt.Println("----------------------")
		// test on arrays
		str = "test jsonpath conditions on arrays"
		fmt.Println(str)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_1container.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_conditions_LT_and_LT_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		//test on arrays with IN, NIN
		str = "test jsonpath conditions on arrays with IN/NIN"
		fmt.Println(str)

		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a3.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a4.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a5.json")
		So(results[0], ShouldEqual, DEFAULT)

		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a3.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a4.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a5.json")
		So(results[0], ShouldEqual, ALLOW)

		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_no_a_no_b1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_no_a_no_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_b.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_no_b.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_some_b.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_IN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_some_a_some_b.json")
		So(results[0], ShouldEqual, DEFAULT)

		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_no_a_no_b1.json")
		So(results[0], ShouldEqual, DEFAULT) // test on empty jsonpath result is false by default
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_no_a_no_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_b2.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_no_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_a_some_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NIN_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_labels_some_a_some_b.json")
		So(results[0], ShouldEqual, DEFAULT)

		fmt.Println("----------------------")

		// more tests on EX/NEX
		str = "test jsonpath conditions EX/NEX"
		fmt.Println(str)
		//// empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data

		//// not-empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, ALLOW)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1b.json")
		So(results[0], ShouldEqual, ALLOW)

		// test on EX/NEX with arrays
		str = "test jsonpath conditions EX/NEX with arrays"
		fmt.Println(str)
		//// empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data

		//// not-empty raw data
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_EX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, DEFAULT)
		results = test_CheckMessagesWithJsonRaw("../examples/rules_with_jsonpath_NEX_on_array.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, ALLOW)

		//-------------------------------------------------------------------------------------------------------------------------------------------------
		str = "test rules for istio's bookinfo app"
		fmt.Println(str)
		results = test_CheckMessages("../examples/rules_istio.yaml", "../examples/messages_istio.yaml")
		So(results[0], ShouldEqual, ALLOW)
		fmt.Println("----------------------")
	})
}

// Test_CheckMessages reads the rules and messages from yaml files and output the decision for each message to the stdout
func test_CheckMessages(rulesFilename string, messagesFilename string) []int {

	rules := YamlReadRulesFromFile(rulesFilename)
	messages := YamlReadMessagesFromFile(messagesFilename)

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		result, msg, relevantRuleIndex, _, appliedRulesIndices , _:= Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}
	return outputResults
}

func read_binary_file(filename string) ([]byte, error) {

	file, err := os.Open(filename)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// calculate the bytes size
	var size int64 = info.Size()
	bytes := make([]byte, size)

	// read into buffer
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(bytes)
	return bytes, err
}

func test_CheckMessagesWithJsonRaw(rulesFilename string, messagesFilename string, jsonRawFilename string) []int {

	rules := YamlReadRulesFromFile(rulesFilename)
	messages := YamlReadMessagesFromFile(messagesFilename)
	data, err := read_binary_file(jsonRawFilename)
	if err!=nil{
		panic("can't read json raw file")
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		message.RequestJsonRaw = &data

		result, msg, relevantRuleIndex, _, appliedRulesIndices , _:= Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}
	return outputResults
}

// Test_MD5Hash reads the rules outputs the MD5 hash of the rule
func test_MD5Hash(rulesFilename string) []string {

	rules := YamlReadRulesFromFile(rulesFilename)
	var outputHashes []string
	for i_rule, rule := range (rules.Rules) {

		md5hash := RuleMD5Hash(rule)
		fmt.Printf("rule #%v: md5hash = %v\n", i_rule, md5hash)
		outputHashes = append(outputHashes, md5hash)
	}
	return outputHashes
}
