package MAPL_engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bhmj/jsonslice"
	"github.com/ghodss/yaml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
)

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

		results, _ := test_CheckMessages("../files/rules/basic_rules/rules_basic_v2.yaml", "../files/messages/main_fields/messages_basic_sender_name.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

	})
}

// TODO: test json path with '*'
func TestRuleHashes(t *testing.T) { //To-do: re-write

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
		hashes, _ := test_MD5Hash("../files/rules/hash_test/rules_with_label_conditions_for_hash_tests.yaml")
		So(hashes[0], ShouldEqual, hashes[1])
		So(hashes[0], ShouldEqual, hashes[6])
		So(hashes[0], ShouldEqual, hashes[7])
		So(hashes[2], ShouldEqual, hashes[4])
		So(hashes[3], ShouldNotEqual, hashes[0])
		So(hashes[3], ShouldNotEqual, hashes[2])
		So(hashes[5], ShouldNotEqual, hashes[0])
		So(hashes[5], ShouldNotEqual, hashes[2])
		fmt.Println("----------------------")
	})
}

func TestMaplEngineMainFields(t *testing.T) {

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
		/*
			str := "test whitelist: sender. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry), message 2: block by default (no relevant whitelist entry)  message 3: block by default (no relevant whitelist entry)"
			fmt.Println(str)
			results, _ := test_CheckMessages("../files/rules/main_fields/rules_basic.yaml", "../files/messages/main_fields/messages_basic_sender_name.yaml")
			So(results[0], ShouldEqual, ALLOW)
			So(results[1], ShouldEqual, DEFAULT)
			So(results[2], ShouldEqual, DEFAULT)
			So(results[3], ShouldEqual, DEFAULT)
			fmt.Println("----------------------")

			str = "test whitelist: receiver. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry)"
			fmt.Println(str)
			results, _ = test_CheckMessages("../files/rules/main_fields/rules_basic.yaml", "../files/messages/main_fields/messages_basic_receiver_name.yaml")
			So(results[0], ShouldEqual, ALLOW)
			So(results[1], ShouldEqual, DEFAULT)
			fmt.Println("----------------------")

			str = "test whitelist: sender with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
			fmt.Println(str)
			results, _ = test_CheckMessages("../files/rules/main_fields/rules_sender_with_wildcards.yaml", "../files/messages/main_fields/messages_sender_name_test_with_wildcards.yaml")
			So(results[0], ShouldEqual, ALLOW)
			So(results[1], ShouldEqual, ALLOW)
			So(results[2], ShouldEqual, DEFAULT)
			So(results[3], ShouldEqual, DEFAULT)
			fmt.Println("----------------------")

			str = "test whitelist: receiver with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
			fmt.Println(str)
			results, _ = test_CheckMessages("../files/rules/main_fields/rules_receiver_with_wildcards.yaml", "../files/messages/main_fields/messages_receiver_name_test_with_wildcards.yaml")
			So(results[0], ShouldEqual, ALLOW)
			So(results[1], ShouldEqual, ALLOW)
			So(results[2], ShouldEqual, DEFAULT)
			So(results[3], ShouldEqual, DEFAULT)
			fmt.Println("----------------------")

			str = "test whitelist: sender lists. Expected results: messages 0,1: allow, messages 2: block by default (no relevant whitelist entry)"
			fmt.Println(str)
			results, _ = test_CheckMessages("../files/rules/main_fields/rules_sender_list.yaml", "../files/messages/main_fields/messages_sender_test_with_lists.yaml")
			So(results[0], ShouldEqual, ALLOW)
			So(results[1], ShouldEqual, ALLOW)
			So(results[2], ShouldEqual, DEFAULT)
			fmt.Println("----------------------")
		*/
		str := "test whitelist: sender ip. Expected results: message 0,1,3,4: allow, message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ := test_CheckMessages("../files/rules/main_fields/rules_with_sender_ips.yaml", "../files/messages/main_fields/messages_basic_sender_ip.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: receiver ip. message 2: allow, messages 0,1: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_with_receiver_ips.yaml", "../files/messages/main_fields/messages_basic_receiver_ip.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "est whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block , message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_resources.yaml", "../files/messages/main_fields/messages_resources.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_resources_with_wildcards.yaml", "../files/messages/main_fields/messages_resources_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		fmt.Println("----------------------")

		str = "test whitelist: resources with lists. Expected results: messages 0,1: alert, message 2: block"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_resource_lists.yaml", "../files/messages/main_fields/messages_resources_test_with_lists.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, ALERT)
		So(results[2], ShouldEqual, BLOCK)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		So(results[5], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: operations. Expected results: messages 0: allow, messages 1: block , message 2: block by default (no relevant whitelist entry), message 3: allow, message 4: block , message 5: block"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_operations.yaml", "../files/messages/main_fields/messages_operations.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: operations with lists. Expected results: messages 1,2: allow, messages 0,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_operation_list.yaml", "../files/messages/main_fields/messages_operations_test_with_list.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		//-------------------------------------------------------------------------------------------------------------------------------------------------
		str = "test rules for istio's bookinfo app"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/main_fields/rules_istio.yaml", "../files/messages/main_fields/messages_istio.yaml")
		So(results[0], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

	})
}

func TestMaplEngineConditions(t *testing.T) {

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

		// test whitelist: conditions. Expected results:
		// messages 0: allow by rule 0 (allows everything)
		// messages 1: block by condition on payloadSize
		// messages 2: block by condition on payloadSize
		// messages 3: allow by rule 0 (allows everything)
		// messages 4: block by condition on utcHoursFromMidnight
		// messages 5: block by condition on payloadSize and utcHoursFromMidnight
		str := "test whitelist: conditions. 0,3: allow, 1,2,4,5: block by conditions"
		fmt.Println(str)
		results, _ := test_CheckMessages("../files/rules/with_conditions/rules_with_conditions.yaml", "../files/messages/conditions/messages_test_with_conditions.yaml")
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
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_label_conditions.yaml", "../files/messages/conditions/messages_test_with_label_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, ALLOW)
		So(results[4], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: conditions with sender and receiver namespaces"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_namespace_conditions.yaml", "../files/messages/conditions/messages_test_with_namespace_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW) // by rule 2
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW) // by rule 0
		So(results[3], ShouldEqual, ALLOW) // by rule 1
		So(results[4], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		// test whitelist: conditions on encryption. Expected results:
		// messages 0: block by default
		// messages 1: block by default
		// messages 2: allow by condition on encryption

		str = "test encryption conditions: 0,1: block by default, 2: allow by conditions on encryption"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_encryption_conditions.yaml", "../files/messages/conditions/messages_test_with_encryption_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test EX and NEX methods"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_EX_conditions.yaml", "../files/messages/conditions/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, BLOCK)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_NEX_conditions.yaml", "../files/messages/conditions/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, BLOCK)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test IN and NIN methods"
		fmt.Println(str)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_IN_conditions.yaml", "../files/messages/conditions/messages_test_with_IN_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessages("../files/rules/with_conditions/rules_with_NIN_conditions.yaml", "../files/messages/conditions/messages_test_with_IN_conditions.yaml")
		So(results[0], ShouldEqual, BLOCK)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, BLOCK)
		So(results[3], ShouldEqual, BLOCK)
		So(results[4], ShouldEqual, BLOCK)
		fmt.Println("----------------------")

	})
}

func TestMaplEngineJsonConditionsDebugging(t *testing.T) {

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

		results, _ := test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug4.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug4b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug2.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, err := test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug.json")
		fmt.Println(err)

		So(err, ShouldEqual, nil)

		results, _ = test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug.json")
		So(results[0], ShouldEqual, BLOCK)
		results2, _ := test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug.json")
		So(results2[0], ShouldEqual, BLOCK)

		results3, _ := test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/yaml_raw_data_debug.yaml")
		So(results3[0], ShouldEqual, BLOCK)
		results4, _ := test_CheckMessagesWithRawData("../files/rules/debugging/rules_with_jsonpath_debug2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/yaml_raw_data_debug.yaml")
		So(results4[0], ShouldEqual, DEFAULT)

		results5, _ := test_ConditionsWithJsonRaw("../files/rules/debugging/rules_with_jsonpath_debug.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug.json")
		So(results5[0][0], ShouldEqual, true)
		results6, _ := test_ConditionsWithJsonRaw("../files/rules/debugging/rules_with_jsonpath_debug2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/debugging/json_raw_data_debug.json")
		So(results6[0][0], ShouldEqual, true)

	})
}

func TestMaplEngineJsonConditionWithReturnValues(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath condition"
		fmt.Println(str)

		results, extraData, _ := test_CheckMessagesWithRawDataWithReturnValue("../files/rules/condition_keyword/rules_with_condition_keyword_and_return_value.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_condition_with_return_values.json")
		So(len(extraData[0]), ShouldEqual, 1)
		So(len(extraData[0][0]), ShouldEqual, 2)
		So(extraData[0][0]["name"], ShouldEqual, "containerName")
		So(extraData[0][0]["command"], ShouldEqual, "containerCommand")
		So(results[0], ShouldEqual, ALLOW)
	})
}

func TestMaplEngineJsonConditionsWildcards(t *testing.T) {

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

		if false {
			data := []byte(`{
		     "apiVersion": "v1",
		     "kind": "Pod",
		     "spec": {
		       "containers": [
		         {
		           "name": "c1",
		           "image": "busybox",
		           "resources": {
		             "limits": {
		               "cpu": "2"
		             }
		           }
		         },
		         {
		           "name": "c2",
		           "image": "busybox",
		           "resources": {
		             "limits": {
		               "cpu": "2"
		             }
		           }
		         }
		       ]
		     }
		   }`)

			z1, err := jsonslice.Get(data, "$.spec.containers[:]")
			if err == nil {
				fmt.Println(string(z1))
			}
			var x interface{}
			err = json.Unmarshal(z1, &x)
			z1, err = json.Marshal(x)
			z2, err := jsonslice.Get(data, "$.spec.containers")
			err = json.Unmarshal(z2, &x)
			z2, err = json.Marshal(x)
			if err == nil {
				fmt.Println(string(z2))
			}
			So(len(z1), ShouldEqual, len(z2))
			for i_z, _ := range (z1) {
				So(z1[i_z], ShouldEqual, z2[i_z])
			}

			z3, err := jsonslice.Get(data, "$..spec.containers[:]")
			err = json.Unmarshal(z3, &x)
			z3b, err := json.Marshal(x)
			if err == nil {
				fmt.Println(string(z3))
			}
			z4, err := jsonslice.Get(data, "$..spec.containers")
			err = json.Unmarshal(z4, &x)
			z4b, err := json.Marshal(x)
			if err == nil {
				fmt.Println(string(z4))
			}
			So(len(z3b), ShouldEqual, len(z4b))
			for i_z, _ := range (z3b) {
				So(z3b[i_z], ShouldEqual, z4b[i_z])
			}
		}

		results, extraData, _ := test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers.json")
		So(extraData[0][0]["name"].(string), ShouldEqual, "c2")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers.json")
		So(extraData[0][0]["name"].(string), ShouldEqual, "c2")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers_dep.json")
		So(len(extraData[0]), ShouldEqual, 0)
		So(results[0], ShouldEqual, DEFAULT)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers_dep.json")
		So(extraData[0][0]["name"].(string), ShouldEqual, "c2")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers_dep2.json")
		So(extraData[0][0]["name"].(string), ShouldEqual, "c2A")
		So(extraData[0][1]["name"].(string), ShouldEqual, "c2B")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/deepscan/rules_with_jsonpath_deepscan2b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/deepscan/json_raw_data_2containers_dep2.json")
		So(extraData[0][0]["name"].(string), ShouldEqual, "c2A")
		So(extraData[0][1]["name"].(string), ShouldEqual, "c2B")
		So(results[0], ShouldEqual, BLOCK)
	})
}

func TestMaplEngineJsonConditions(t *testing.T) {

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

		str := "test jsonpath conditions"
		fmt.Println(str)
		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_GT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_GT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_EQ.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_foo.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_foofoo.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, BLOCK)

		// EX:
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists0.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists1.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, BLOCK)

		// NEX:
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists0b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists1b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_key_exists2b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_annotations_EQ.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data3.json")
		So(results[0], ShouldEqual, BLOCK)

		// more tests on EX/NEX
		str = "test jsonpath conditions EX/NEX"
		fmt.Println(str)
		//// empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_NEX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data

		//// not-empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_NEX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_NEX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1b.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_B.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_C.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_D.json")
		So(results[0], ShouldEqual, DEFAULT)

	})
}

func TestMaplEngineJsonConditions_NOT(t *testing.T) {

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

		str := "test jsonpath conditions"
		fmt.Println(str)
		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_GT_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_GT_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_EQ_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_foo_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_foofoo_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, DEFAULT)

		// EX:
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists0_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists1_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists2_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, DEFAULT)

		// NEX:
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists0b_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists1b_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_label_key_exists2b_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1a.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_annotations_EQ_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data3.json")
		So(results[0], ShouldEqual, DEFAULT)

		// more tests on EX/NEX
		str = "test jsonpath conditions EX/NEX"
		fmt.Println(str)
		//// empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, BLOCK) // always false for empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_NEX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, BLOCK) // always false for empty raw data

		//// not-empty raw data
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_NEX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_NEX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data1b.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_B.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_C.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data_2containers_cpu_missing_from_one_D.json")
		So(results[0], ShouldEqual, BLOCK)

		// x and not y:
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_AND_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4a.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_AND_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_AND_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4c.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_NOT_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4a.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_NOT_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_NOT_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4c.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_NOT/rules_with_jsonpath_conditions_labels_NOT_OR_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data4d.json")
		So(results[0], ShouldEqual, BLOCK)

	})
}

func TestMaplEngineJsonConditionsOnArraysAny(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions on arrays"
		fmt.Println(str)

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, DEFAULT)

	})
}

func TestMaplEngineJsonConditionsOnArraysAny_NOT(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions on arrays"
		fmt.Println(str)

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, BLOCK)

	})
}

// The main test calls Test_CheckMessages with different sets of rule and message yaml files as inputs. The rule and message yaml files are stored in the examples folder.
func TestMaplEngineJsonConditionsOnArraysAll(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions on arrays"
		fmt.Println(str)

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, DEFAULT)
		//-----------
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A3.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A4.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A5.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A6.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A7.json")
		So(results[0], ShouldEqual, BLOCK)

	})
}
func TestMaplEngineJsonConditionsOnArraysAll_NOT(t *testing.T) {

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

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, BLOCK)
		//-----------
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A3.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A4.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A5.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A6.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_NOT/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX_NOT.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu_missing_from_one_A7.json")
		So(results[0], ShouldEqual, DEFAULT)
	})
}

// The main test calls Test_CheckMessages with different sets of rule and message yaml files as inputs. The rule and message yaml files are stored in the examples folder.
func TestMaplEngineJsonConditionsOnArraysAnyAll2(t *testing.T) {

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

		// test on arrays
		str := "test more jsonpath conditions on arrays"
		fmt.Println(str)
		//test on arrays with EQ, NEQ
		str = "test jsonpath conditions on arrays with EQ/NEQ (the test returns true if one of the array value passes)"
		fmt.Println(str)

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_EQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_EQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_EQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ3.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NEQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NEQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NEQ_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_EQ3.json")
		So(results[0], ShouldEqual, BLOCK)

		fmt.Println("----------------------")

		//test on arrays with IN, NIN
		str = "test jsonpath conditions on arrays with IN/NIN (the test returns true if one of the array value passes)"
		fmt.Println(str)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a3.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a4.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a5.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a3.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a4.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a5.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_no_a_no_b1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_no_a_no_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_no_b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_some_b.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_IN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_some_a_some_b.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_no_a_no_b1.json")
		So(results[0], ShouldEqual, DEFAULT) // test on empty jsonpath result is false by default
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_no_a_no_b2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_b2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_no_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_a_some_b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NIN_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_labels_some_a_some_b.json")
		So(results[0], ShouldEqual, DEFAULT)

		fmt.Println("----------------------")
		//test on arrays with RE, NRE
		str = "test jsonpath conditions on arrays with RE/NRE (the test returns true if one of the array value passes)"
		fmt.Println(str)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_no_images.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_one_image_no_abc.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_one_image_abc.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_no_abc.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_one_abc.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_two_abc.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/basic_jsonpath/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_no_images.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_one_image_no_abc.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_one_image_abc.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_no_abc.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_one_abc.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NRE_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_two_images_two_abc.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_EX_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_cpu_not_missing.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_NEX_on_array.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_2containers_cpu_not_missing.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY2/rules_with_jsonpath_RE_on_array2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all2/json_raw_data_password_in_env.json")
		So(results[0], ShouldEqual, BLOCK)

	})
}

func TestMaplEngineJsonConditionsOnArraysAnyReturnValues(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions on arrays"
		fmt.Println(str)

		results, extraData, _ := test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		So(len(extraData[0]), ShouldEqual, 0)
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		val := extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		//So(extraData[0], ShouldEqual, "c1")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(len(extraData[0]), ShouldEqual, 0)
		So(results[0], ShouldEqual, DEFAULT)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		//So(extraData[0], ShouldEqual, "c1")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		//So(extraData[0], ShouldEqual, "c1")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		valBytes, _ := json.Marshal(extraData[0][0]["resources"])
		val = string(valBytes)
		val2 := `{"limits":{"cpu":"2","memory":"1000Mi"}}`
		So(val, ShouldEqual, val2)
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		e.Encode(extraData[0][0]["all"]) // we use encode instead of marshal so that we do not translate to utf-8 for easier comparison of strings
		//valBytes,_=json.Marshal(extraData[0][0]["all"])
		//val=string(valBytes)
		val = buf.String()
		val = val[0 : len(val)-1] // since Encode adds a line break
		val2 = `{"command":["sh","-c","echo 'Hello1 AppArmor!' && sleep 1h"],"image":"busybox","name":"c1","resources":{"limits":{"cpu":"2","memory":"1000Mi"}}}`
		So(val, ShouldEqual, val2)
		So(results[0], ShouldEqual, BLOCK)

		//-----------
		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000d.json")
		//So(extraData[0], ShouldEqual, "c1,c2")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c2")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000d.json")
		// first container that pass the ANY [0][0]
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		valBytes, _ = json.Marshal(extraData[0][0]["resources"])
		val = string(valBytes)
		val2 = `{"limits":{"cpu":"2","memory":"1000Mi"}}`
		So(val, ShouldEqual, val2)
		buf.Reset()
		e.Encode(extraData[0][0]["all"]) // we use encode instead of marshal so that we do not translate to utf-8 for easier comparison of strings
		val = buf.String()
		val = val[0 : len(val)-1] // since Encode adds a line break
		val2 = `{"command":["sh","-c","echo 'Hello1 AppArmor!' && sleep 1h"],"image":"busybox","name":"c1","resources":{"limits":{"cpu":"2","memory":"1000Mi"}}}`
		So(val, ShouldEqual, val2)

		// second container that pass the ANY [0][1]
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c2")
		valBytes, _ = json.Marshal(extraData[0][1]["resources"])
		val = string(valBytes)
		val2 = `{"limits":{"cpu":"1","memory":"1100Mi"}}`
		So(val, ShouldEqual, val2)
		buf.Reset()
		e.Encode(extraData[0][1]["all"]) // we use encode instead of marshal so that we do not translate to utf-8 for easier comparison of strings
		val = buf.String()
		val = val[0 : len(val)-1] // since Encode adds a line break
		val2 = `{"command":["sh","-c","echo 'Hello AppArmor!' && sleep 2h"],"image":"busybox","name":"c2","resources":{"limits":{"cpu":"1","memory":"1100Mi"}}}`
		So(val, ShouldEqual, val2)

		So(results[0], ShouldEqual, BLOCK)

		strBytes, _ := json.Marshal(extraData[0])
		fmt.Println(string(strBytes))

		//-----------

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000e.json")
		//So(extraData[0], ShouldEqual, "c1,c3")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c3")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2b.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000e.json")
		//So(extraData[0], ShouldEqual, "c1,c3")
		// first container that pass the ANY [0][0]
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		valBytes, _ = json.Marshal(extraData[0][0]["resources"])
		val = string(valBytes)
		val2 = `{"limits":{"cpu":"2","memory":"1000Mi"}}`
		So(val, ShouldEqual, val2)
		buf.Reset()
		e.Encode(extraData[0][0]["all"]) // we use encode instead of marshal so that we do not translate to utf-8 for easier comparison of strings
		val = buf.String()
		val = val[0 : len(val)-1] // since Encode adds a line break
		val2 = `{"command":["sh","-c","echo 'Hello1 AppArmor!' && sleep 1h"],"image":"busybox","name":"c1","resources":{"limits":{"cpu":"2","memory":"1000Mi"}}}`
		So(val, ShouldEqual, val2)
		// second container that pass the ANY [0][1]
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c3")
		valBytes, _ = json.Marshal(extraData[0][1]["resources"])
		val = string(valBytes)
		val2 = `{"limits":{"cpu":"1","memory":"1100Mi"}}`
		So(val, ShouldEqual, val2)
		buf.Reset()
		e.Encode(extraData[0][1]["all"]) // we use encode instead of marshal so that we do not translate to utf-8 for easier comparison of strings
		val = buf.String()
		val = val[0 : len(val)-1] // since Encode adds a line break
		val2 = `{"command":["sh","-c","echo 'Hello1 AppArmor!' && sleep 3h"],"image":"busybox","name":"c3","resources":{"limits":{"cpu":"1","memory":"1100Mi"}}}`
		So(val, ShouldEqual, val2)

		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000f.json")
		//So(extraData[0], ShouldEqual, "c3")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c3")
		So(results[0], ShouldEqual, BLOCK)

		//---------

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_1container.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000b.json")
		So(len(extraData[0]), ShouldEqual, 0)
		So(results[0], ShouldEqual, DEFAULT)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000c.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000d.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c2")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000e.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1")
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c3")
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000f.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c3")
		So(results[0], ShouldEqual, BLOCK)

		//---------------
		// OR with two ANYs
		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY4.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000g.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c1") // the first (2 ANYs under OR)
		So(results[0], ShouldEqual, BLOCK)

		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY4.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000h.json")
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c2") // the first (2 ANYs under OR)
		So(results[0], ShouldEqual, BLOCK)

		//---------------
		// AND with two ANYs
		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY7.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000g.json")
		val = extraData[0][0]["name2"].(string)
		So(val, ShouldEqual, "c2") // the last (2 ANYs under AND)
		So(results[0], ShouldEqual, BLOCK)

		//---------------
		// NOT with ANY
		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY5.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000h.json")
		So(len(extraData[0]), ShouldEqual, 0) // NOT removes the extraData from the ANY node
		So(results[0], ShouldEqual, BLOCK)

		//---------
		// with units
		results, extraData, _ = test_CheckMessagesWithRawDataWithReturnValue("../files/rules/with_jsonpath_conditions_ALL_ANY/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY6.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/any_all/json_raw_data_2containers_cpu2_mem2000i.json")
		So(len(extraData[0]), ShouldEqual, 3)
		val = extraData[0][0]["name"].(string)
		So(val, ShouldEqual, "c2")
		val = extraData[0][1]["name"].(string)
		So(val, ShouldEqual, "c4")
		val = extraData[0][2]["name"].(string)
		So(val, ShouldEqual, "c6")
		So(results[0], ShouldEqual, BLOCK)

	})
}

// The main test calls Test_CheckMessages with different sets of rule and message yaml files as inputs. The rule and message yaml files are stored in the examples folder.
func TestMaplEngineJsonConditionsOnArraysMultilevel(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions on arrays"
		fmt.Println(str)

		results, _ := test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData("../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_C.json")
		So(results[0], ShouldEqual, DEFAULT)

	})
}

func TestRuleValidation(t *testing.T) {

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

		isvalid_all, err := test_RuleValidity("../files/rules/invalid_rules/invalid_rule_name_list.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_RE.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_Attribute.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_Attribute2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_Method.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_mismatch_between_att_val.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_mismatch_between_att_val2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/valid_rule_match_between_att_val.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, true)
		So(err, ShouldEqual, nil)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions3.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions_ANY.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions_ANY2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions_ANY3.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		//		isvalid_all, err = test_RuleValidity("../files/rules/invalid_rules/invalid_rule_conditions_ANY4.yaml") // this rule is valid since we do not require the parentAttribute to end with [:]!
		//		fmt.Println(err)
		//		So(isvalid_all, ShouldEqual, false)

		//----------------------
		isvalid_all, _ = test_RuleValidity("../files/rules/invalid_rules/valid_rule_RE.yaml")
		So(isvalid_all, ShouldEqual, true)

		isvalid_all, _ = test_RuleValidity("../files/rules/invalid_rules/one_valid_one_invalid_rule_RE.yaml")
		So(isvalid_all, ShouldEqual, false)

	})
}

func TestRulesWithPredefinedStrings(t *testing.T) {

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

		results, rules, err := test_CheckMessagesWithPredefinedStrings("../files/rules/predefined_strings/rules_with_sender_translation_invalid.yaml", "../files/messages/predefined_strings/messages_basic_sender_name.yaml", "../files/lists/predefined_string.yaml")
		errStr := fmt.Sprintf("%v", err)
		So(errStr, ShouldEqual, "sender name is not predefined [#not_existing]")

		results, rules, _ = test_CheckMessagesWithPredefinedStrings("../files/rules/predefined_strings/rules_with_sender_translation.yaml", "../files/messages/predefined_strings/messages_basic_sender_name.yaml", "../files/lists/predefined_string.yaml")
		So(rules.Rules[0].preparedRule.Sender.SenderName, ShouldEqual, "abc")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)

		results, rules, _ = test_CheckMessagesWithPredefinedStrings("../files/rules/predefined_strings/rules_with_receiver_translation.yaml", "../files/messages/predefined_strings/messages_basic_receiver_name.yaml", "../files/lists/predefined_string.yaml")
		So(rules.Rules[0].preparedRule.Receiver.ReceiverName, ShouldEqual, "abc")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)

		results, rules, _ = test_CheckMessagesWithPredefinedStrings("../files/rules/predefined_strings/rules_with_sender_translation_list.yaml", "../files/messages/predefined_strings/messages_basic_sender_name.yaml", "../files/lists/predefined_list.yaml")
		So(rules.Rules[0].preparedRule.Sender.SenderName, ShouldEqual, "abc,def")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)

		results, rules, _ = test_CheckMessagesWithPredefinedStrings("../files/rules/predefined_strings/rules_with_receiver_translation_list.yaml", "../files/messages/predefined_strings/messages_basic_receiver_name.yaml", "../files/lists/predefined_list.yaml")
		So(rules.Rules[0].preparedRule.Receiver.ReceiverName, ShouldEqual, "abc,def")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)

		//---------
		predefined_lists := []string{"../files/lists/predefined_list_workload.yaml", "../files/lists/predefined_list_workload2.yaml", "../files/lists/predefined_list_workload3.yaml", "../files/lists/predefined_list_workload4.yaml"}
		for _, f := range (predefined_lists) {
			results, rules, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_dep.json", f)
			z := rules.Rules[0].preparedRule.Conditions.ConditionsTree.String()
			//So(z, ShouldEqual, "<jsonpath:$.kind-RE-^Deployment$|^Pod$>")
			So(z, ShouldEqual, "<jsonpath:$.kind-IN-Deployment,Pod>")
			So(results[0], ShouldEqual, ALLOW)

			results, rules, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod.json", f)
			So(results[0], ShouldEqual, ALLOW)

			results, rules, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_job.json", f)
			So(results[0], ShouldEqual, DEFAULT)
		}
		//---------

		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)

		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_bar.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_XbarX.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_xyz.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_abc.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)

		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_bar.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_XbarX.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_xyz.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_abc.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)

		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_bar.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_XbarX.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_xyz.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_abc.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)

		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_bar.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_XbarX.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_xyz.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, ALLOW)
		results, _, _ = test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/predefined_strings/json_raw_workload_pod_abc.json", "../files/lists/predefined_list_allowed_labels.yaml")
		So(results[0], ShouldEqual, DEFAULT)

	})
}

func TestMaplEngineJsonConditionsKeyValue(t *testing.T) {

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

		// test on arrays
		str := "test jsonpath conditions with key/value attribute"
		fmt.Println(str)


		results, _ := test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_key1.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_key2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_key3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value1.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_json.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_json2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative2.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative3.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative2.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_value_relative_ALL.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative3.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData("../files/rules/key_value/rules_with_jsonpath_conditions_key_relative.yaml", "../files/messages/messages_base_jsonpath.yaml", "../files/raw_json_data/key_value/json_raw_data_object.json")
		So(results[0], ShouldEqual, BLOCK)


	})
}

func TestRulesWithPredefinedStringsZooz(t *testing.T) {

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

		for i := 1; i <= 19; i++ {
			f := fmt.Sprintf("../files/raw_json_data/predefined_strings/json_raw_zooz_%v.json", i)
			results, _, _ := test_CheckMessagesWithRawDataAndPredefinedStrings("../files/rules/predefined_strings/rule_zooz.yaml", "../files/messages/messages_base_jsonpath.yaml", f, "../files/lists/predefined_password_list.yaml")
			So(results[0], ShouldEqual, BLOCK)
			fmt.Printf("zooz test #%v passed\n", i)
		}
	})
}

// Test_CheckMessages reads the rules and messages from yaml files and output the decision for each message to the stdout
func test_CheckMessages(rulesFilename string, messagesFilename string) ([]int, error) {

	rules, err := YamlReadRulesFromFile(rulesFilename)
	if err != nil {
		return []int{}, err
	}
	fmt.Printf("rules = %+v\n", rules)

	messages, err := YamlReadMessagesFromFile(messagesFilename)
	if err != nil {
		return []int{}, err
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _, _ := Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

		result2 := DEFAULT
		for _, r := range rules.Rules {
			result2_temp, _ := r.Check(&message)
			if result2_temp > result2 {
				result2 = result2_temp
			}
		}
		So(result, ShouldEqual, result2)

	}

	return outputResults, nil

}

// Test_CheckMessages reads the rules and messages from yaml files and output the decision for each message to the stdout
func test_CheckMessagesWithPredefinedStrings(rulesFilename string, messagesFilename string, stringListFilename string) ([]int, Rules, error) {

	predefinedStringsAndLists, err := YamlReadStringListsFromFile(stringListFilename)
	fmt.Println(predefinedStringsAndLists)

	rules, err := YamlReadRulesFromFileWithPredefinedStrings(rulesFilename, predefinedStringsAndLists)
	if err != nil {
		return []int{}, rules, err
	}
	fmt.Printf("rules = %+v\n", rules)

	messages, err := YamlReadMessagesFromFile(messagesFilename)
	if err != nil {
		return []int{}, rules, err
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _, _ := Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

		for _, r := range rules.Rules {
			result2, _ := r.Check(&message)
			So(result, ShouldEqual, result2)
		}

	}

	err = SetGlobalPredefinedStringsAndLists(predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = SetGlobalPredefinedStringsAndLists(PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)

	return outputResults, rules, nil

}

func readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename, stringListFilename string) (Rules, Messages, []byte, error) {

	predefinedStringsAndLists := PredefinedStringsAndLists{}
	err := fmt.Errorf("error")
	if len(stringListFilename) > 0 {
		predefinedStringsAndLists, err = YamlReadStringListsFromFile(stringListFilename)
		if err != nil {
			fmt.Printf("error: %v", err)
			return Rules{}, Messages{}, []byte{}, err
		}
	}
	rules, err := YamlReadRulesFromFileWithPredefinedStrings(rulesFilename, predefinedStringsAndLists)
	if err != nil {
		fmt.Printf("error: %v", err)
		return Rules{}, Messages{}, []byte{}, err
	}
	messages, err := YamlReadMessagesFromFile(messagesFilename)
	if err != nil {
		return Rules{}, Messages{}, []byte{}, err
	}
	data, err := ReadBinaryFile(rawFilename)
	if err != nil {
		fmt.Printf("can't read json raw file")
		return Rules{}, Messages{}, []byte{}, err
	}
	isYaml := strings.HasSuffix(rawFilename, ".yaml")
	if isYaml {
		data2, err := yaml.YAMLToJSON(data)
		if err != nil {
			return Rules{}, Messages{}, []byte{}, err
		}
		data = data2
	}

	return rules, messages, data, nil
}

func test_CheckMessagesWithRawData(rulesFilename, messagesFilename, rawFilename string) ([]int, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename, "")
	if err != nil {
		return []int{}, err
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		message.RequestJsonRaw = &data

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _, _ := Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}
	return outputResults, nil
}

func test_CheckMessagesWithRawDataWithReturnValue(rulesFilename, messagesFilename, rawFilename string) ([]int, [][]map[string]interface{}, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename, "")
	if err != nil {
		return []int{}, [][]map[string]interface{}{}, err
	}

	var outputResults []int
	var outputResultsExtraData [][]map[string]interface{}

	for i_message, message := range (messages.Messages) {

		message.RequestJsonRaw = &data

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _, extraData := Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)
		outputResultsExtraData = append(outputResultsExtraData, extraData[0])
	}
	return outputResults, outputResultsExtraData, nil
}

func test_CheckMessagesWithRawDataAndPredefinedStrings(rulesFilename, messagesFilename, rawFilename, stringsAndListsFilename string) ([]int, Rules, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename, stringsAndListsFilename)
	if err != nil {
		return []int{}, Rules{}, err
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		message.RequestJsonRaw = &data

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _, _ := Check(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}
	return outputResults, rules, nil
}

func test_ConditionsWithJsonRaw(rulesFilename string, messagesFilename string, rawFilename string) ([][]bool, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename, "")
	if err != nil {
		return [][]bool{}, err
	}

	var outputResults [][]bool
	outputResults = make([][]bool, len(messages.Messages))
	var outputResultsExtraData [][][]map[string]interface{}
	outputResultsExtraData = make([][][]map[string]interface{}, len(messages.Messages))
	for i_message, message := range (messages.Messages) {
		outputResults[i_message] = make([]bool, len(rules.Rules))
		outputResultsExtraData[i_message] = make([][]map[string]interface{}, len(rules.Rules))
		for i_rule, rule := range (rules.Rules) {

			message.RequestJsonRaw = &data

			result, extraData := TestConditions(&rule, &message)
			outputResults[i_message][i_rule] = result
			outputResultsExtraData[i_message][i_rule] = extraData

			result2, _ := rule.TestConditions(&message)
			So(result, ShouldEqual, result2)

		}
	}
	return outputResults, nil
}

// test_RuleValidity check the validity of rules in a file
func test_RuleValidity(rulesFilename string) (bool, error) {

	rules, err := YamlReadRulesFromFile(rulesFilename)
	if err != nil {
		return false, err
	}

	for _, r := range (rules.Rules) {
		err = r.SetPredefinedStringsAndLists(PredefinedStringsAndLists{})
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// Test_MD5Hash reads the rules outputs the MD5 hash of the rule
func test_MD5Hash(rulesFilename string) ([]string, error) {

	rules, err := YamlReadRulesFromFile(rulesFilename)
	if err != nil {
		log.Printf("error: =%v", err)
		return []string{}, err
	}

	var outputHashes []string
	for i_rule, rule := range (rules.Rules) {

		md5hash := RuleMD5Hash(rule)
		fmt.Printf("rule #%v: md5hash = %v\n", i_rule, md5hash)
		outputHashes = append(outputHashes, md5hash)
	}
	return outputHashes, nil
}
