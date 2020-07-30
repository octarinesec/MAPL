package MAPL_engine

import (
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

func TestMaplEngineV2(t *testing.T) {

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

		results, _ := test_CheckMessages_v2("../examples_v2/rules_basic_v2.yaml", "../examples/messages_basic_sender_name.yaml")
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
		hashes, _ := test_MD5HashV2("../examples_v2/rules_with_label_conditions_for_hash_tests.yaml")
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

		str := "test whitelist: sender. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry), message 2: block by default (no relevant whitelist entry)  message 3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ := test_CheckMessages_v2("../examples_v2/rules_basic.yaml", "../examples/messages_basic_sender_name.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: receiver. Expected results: message 0: allow, message 1: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_basic.yaml", "../examples/messages_basic_receiver_name.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_sender_with_wildcards.yaml", "../examples/messages_sender_name_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: receiver with wildcards. Expected results: messages 0,1: allow, messages 2,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_receiver_with_wildcards.yaml", "../examples/messages_receiver_name_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender lists. Expected results: messages 0,1: allow, messages 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_sender_list.yaml", "../examples/messages_sender_test_with_lists.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: sender ip. Expected results: message 0,1,3,4: allow, message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_sender_ips.yaml", "../examples/messages_basic_sender_ip.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: receiver ip. message 2: allow, messages 0,1: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_receiver_ips.yaml", "../examples/messages_basic_receiver_ip.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "est whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block , message 2: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_resources.yaml", "../examples/messages_resources.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: resources with wildcards. Expected results: message 0: alert, message 1: block"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_resources_with_wildcards.yaml", "../examples/messages_resources_test_with_wildcards.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, BLOCK)
		fmt.Println("----------------------")

		str = "test whitelist: resources with lists. Expected results: messages 0,1: alert, message 2: block"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_resource_lists.yaml", "../examples/messages_resources_test_with_lists.yaml")
		So(results[0], ShouldEqual, ALERT)
		So(results[1], ShouldEqual, ALERT)
		So(results[2], ShouldEqual, BLOCK)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, ALLOW)
		So(results[5], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test whitelist: operations. Expected results: messages 0: allow, messages 1: block , message 2: block by default (no relevant whitelist entry), message 3: allow, message 4: block , message 5: block"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_operations.yaml", "../examples/messages_operations.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: operations with lists. Expected results: messages 1,2: allow, messages 0,3: block by default (no relevant whitelist entry)"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_operation_list.yaml", "../examples/messages_operations_test_with_list.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		//-------------------------------------------------------------------------------------------------------------------------------------------------
		str = "test rules for istio's bookinfo app"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_istio.yaml", "../examples/messages_istio.yaml")
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
		results, _ := test_CheckMessages_v2("../examples_v2/rules_with_conditions.yaml", "../examples/messages_test_with_conditions.yaml")
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
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_label_conditions.yaml", "../examples/messages_test_with_label_conditions.yaml")
		So(results[0], ShouldEqual, ALLOW)
		So(results[1], ShouldEqual, ALLOW)
		So(results[2], ShouldEqual, ALLOW)
		So(results[3], ShouldEqual, ALLOW)
		So(results[4], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test whitelist: conditions with sender and receiver namespaces"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_namespace_conditions.yaml", "../examples/messages_test_with_namespace_conditions.yaml")
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
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_encryption_conditions.yaml", "../examples/messages_test_with_encryption_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, ALLOW)
		fmt.Println("----------------------")

		str = "test EX and NEX methods"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_EX_conditions.yaml", "../examples/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, BLOCK)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_NEX_conditions.yaml", "../examples/messages_test_with_EX_conditions.yaml")
		So(results[0], ShouldEqual, BLOCK)
		So(results[1], ShouldEqual, DEFAULT)
		So(results[2], ShouldEqual, DEFAULT)
		fmt.Println("----------------------")

		str = "test IN and NIN methods"
		fmt.Println(str)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_IN_conditions.yaml", "../examples/messages_test_with_IN_conditions.yaml")
		So(results[0], ShouldEqual, DEFAULT)
		So(results[1], ShouldEqual, BLOCK)
		So(results[2], ShouldEqual, DEFAULT)
		So(results[3], ShouldEqual, DEFAULT)
		So(results[4], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessages_v2("../examples_v2/rules_with_NIN_conditions.yaml", "../examples/messages_test_with_IN_conditions.yaml")
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

		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_debug.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_debug.json")
		So(results[0], ShouldEqual, BLOCK)
		results2, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_debug2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_debug.json")
		So(results2[0], ShouldEqual, BLOCK)

		results3, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_debug.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/yaml_raw_data_debug.yaml")
		So(results3[0], ShouldEqual, BLOCK)
		results4, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_debug2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/yaml_raw_data_debug.yaml")
		So(results4[0], ShouldEqual, DEFAULT)

		results5, _ := test_ConditionsWithJsonRaw_v2("../examples_v2/rules_with_jsonpath_debug.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_debug.json")
		So(results5[0][0], ShouldEqual, true)
		results6, _ := test_ConditionsWithJsonRaw_v2("../examples_v2/rules_with_jsonpath_debug2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_debug.json")
		So(results6[0][0], ShouldEqual, true)

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


		data:=[]byte(`{
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

		z,err:=jsonslice.Get(data, "$.spec.containers[:]")
		if err==nil {
			fmt.Println(string(z))
		}
		/*z,err=jsonslice.Get(data, "$.spec.containers[*]")
		if err==nil {
			fmt.Println(string(z))
		}
		z,err=jsonslice.Get(data, "$..containers[:]")
		if err==nil {
			fmt.Println(string(z))
		}*/
		z,err=jsonslice.Get(data, "$..spec.containers[:]")
		if err==nil {
			fmt.Println(string(z))
		}


		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_deepscan.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers.json")
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
		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_GT.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_GT.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_EQ.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_foo.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_foofoo.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, BLOCK)

		// EX:
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists0.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists1.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, BLOCK)

		// NEX:
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists0b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists1b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_label_key_exists2b.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1a.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_annotations_EQ.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data3.json")
		So(results[0], ShouldEqual, BLOCK)
		/*
			str:="invalid rules"
			//results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json") //invalid rule
			//So(results[0], ShouldEqual, BLOCK)
			//results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_template_spec_containers.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
			//So(results[0], ShouldEqual, BLOCK)
			//fmt.Println("----------------------")
		*/

		// more tests on EX/NEX
		str = "test jsonpath conditions EX/NEX"
		fmt.Println(str)
		//// empty raw data
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data
		//		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data0.json")
		//		So(results[0], ShouldEqual, DEFAULT) // always false for empty raw data

		//// not-empty raw data
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_NEX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data1b.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_B.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_C.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_AND_OR.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_D.json")
		So(results[0], ShouldEqual, DEFAULT)

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

		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_1container.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, DEFAULT)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, DEFAULT)

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

		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_1container.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000b.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu2_mem2000c.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu3_mem1100.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem1000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu5_mem2000.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_both.json")
		So(results[0], ShouldEqual, DEFAULT)
		//-----------
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A2.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A3.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A4.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A5.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A6.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL_EX.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_cpu_missing_from_one_A7.json")
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

		results, _ := test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, BLOCK)

		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts_B.json")
		So(results[0], ShouldEqual, DEFAULT)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts_B2.json")
		So(results[0], ShouldEqual, BLOCK)
		results, _ = test_CheckMessagesWithRawData_v2("../examples_v2/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../examples/messages_base_jsonpath.yaml", "../examples/json_raw_data_2containers_2volumeMounts_C.json")
		So(results[0], ShouldEqual, DEFAULT)

	})
}

func TestRuleValidationV2(t *testing.T) {

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

		isvalid_all, err := test_RuleValidityV2("../examples_v2/invalid_rule_name_list.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_RE.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_Attribute.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)


		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_Attribute2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_Method.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_mismatch_between_att_val.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_mismatch_between_att_val2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/valid_rule_match_between_att_val.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, true)
		So(err, ShouldEqual, nil)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions3.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions_ANY.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions_ANY2.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions_ANY3.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		isvalid_all, err = test_RuleValidityV2("../examples_v2/invalid_rule_conditions_ANY4.yaml")
		fmt.Println(err)
		So(isvalid_all, ShouldEqual, false)

		//----------------------
		isvalid_all, _ = test_RuleValidityV2("../examples_v2/valid_rule_RE.yaml")
		So(isvalid_all, ShouldEqual, true)

		isvalid_all, _ = test_RuleValidityV2("../examples_v2/one_valid_one_invalid_rule_RE.yaml")
		So(isvalid_all, ShouldEqual, false)

	})
}

// Test_CheckMessages reads the rules and messages from yaml files and output the decision for each message to the stdout
func test_CheckMessages_v2(rulesFilename string, messagesFilename string) ([]int, error) {

	rules, err := YamlReadRulesFromFileV2(rulesFilename)
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

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _ := CheckV2(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}

	return outputResults, nil

}

func readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename string) (RulesV2, Messages, []byte, error) {

	rules, err := YamlReadRulesFromFileV2(rulesFilename)
	if err != nil {
		fmt.Printf("error: %v", err)
		return RulesV2{}, Messages{}, []byte{}, err
	}
	messages, err := YamlReadMessagesFromFile(messagesFilename)
	if err != nil {
		return RulesV2{}, Messages{}, []byte{}, err
	}
	data, err := read_binary_file(rawFilename)
	if err != nil {
		fmt.Printf("can't read json raw file")
		return RulesV2{}, Messages{}, []byte{}, err
	}
	isYaml := strings.HasSuffix(rawFilename, ".yaml")
	if isYaml {
		data2, err := yaml.YAMLToJSON(data)
		if err != nil {
			return RulesV2{}, Messages{}, []byte{}, err
		}
		data = data2
	}

	return rules, messages, data, nil
}

func test_CheckMessagesWithRawData_v2(rulesFilename string, messagesFilename string, rawFilename string) ([]int, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename)
	if err != nil {
		return []int{}, err
	}

	var outputResults []int

	for i_message, message := range (messages.Messages) {

		message.RequestJsonRaw = &data

		result, msg, relevantRuleIndex, _, appliedRulesIndices, _ := CheckV2(&message, &rules)
		if relevantRuleIndex >= 0 {
			fmt.Printf("message #%v: decision=%v [%v] by rule #%v ; applicable rules =%v \n", i_message, result, msg, rules.Rules[relevantRuleIndex].RuleID, appliedRulesIndices)
		} else {
			fmt.Printf("message #%v: decision=%v [%v]\n", i_message, result, msg)
		}
		outputResults = append(outputResults, result)

	}
	return outputResults, nil
}

func test_ConditionsWithJsonRaw_v2(rulesFilename string, messagesFilename string, rawFilename string) ([][]bool, error) {

	rules, messages, data, err := readRulesMessageRawData(rulesFilename, messagesFilename, rawFilename)
	if err != nil {
		return [][]bool{}, err
	}

	var outputResults [][]bool
	outputResults = make([][]bool, len(messages.Messages))
	for i_message, message := range (messages.Messages) {
		outputResults[i_message] = make([]bool, len(rules.Rules))
		for i_rule, rule := range (rules.Rules) {

			message.RequestJsonRaw = &data

			result := TestConditionsV2(&rule, &message)
			outputResults[i_message][i_rule] = result
		}
	}
	return outputResults, nil
}

// test_RuleValidity check the validity of rules in a file
func test_RuleValidityV2(rulesFilename string) (bool, error) {

	_, err := YamlReadRulesFromFileV2(rulesFilename)
	if err != nil {
		return false, err
	}
	return true, nil
}



// Test_MD5Hash reads the rules outputs the MD5 hash of the rule
func test_MD5HashV2(rulesFilename string) ([]string, error) {

	rules, err := YamlReadRulesFromFileV2(rulesFilename)
	if err != nil {
		log.Printf("error: =%v", err)
		return []string{}, err
	}

	var outputHashes []string
	for i_rule, rule := range (rules.Rules) {

		md5hash := RuleMD5HashV2(rule)
		fmt.Printf("rule #%v: md5hash = %v\n", i_rule, md5hash)
		outputHashes = append(outputHashes, md5hash)
	}
	return outputHashes, nil
}
