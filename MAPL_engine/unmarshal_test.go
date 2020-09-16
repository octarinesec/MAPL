package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	dc "gopkg.in/getlantern/deepcopy.v1"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type RuleAndExtras struct {
	MaplRule Rule   `json:"maplRule" binding:"required,dive" bson:"MaplRule"`
	Account  string `json:"account" bson:"account"`
	Enabled  *bool  `json:"enabled,omitempty" bson:"enabled"` // pointer so that we will not have problems with defaults
	Origin   string `json:"origin" bson:"origin"`
}

func TestJsonUnmarhshal(t *testing.T) {

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

		//testUnmarshalForOneFile("../files/rules/predefined_strings/rule_zooz.yaml")

		testUnmarshalForOneFile("../files/rules/with_conditions/rules_with_conditions.yaml")

		var files []string
		var roots []string

		main_root := "../files/rules"

		err := filepath.Walk(main_root, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				if !(path == main_root) {
					if !strings.Contains(path, "predefined_strings") {
						roots = append(roots, path)
					}
				}
			}
			return nil
		})
		if err != nil {
			panic(err)
		}

		for _, root := range (roots) {
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if !info.IsDir() {
					if !strings.Contains(path, "invalid_rule") {
						files = append(files, path)
					}
				}
				return nil
			})
			if err != nil {
				panic(err)
			}
		}

		for _, file := range files {
			fmt.Println(file)
			testUnmarshalForOneFile(file)
		}

		//-----------------------
		var rule Rule
		maplRuleJson := `{"ruleID":"0","sender":{"senderList":[{"Regexp":{},"CIDR":{"IP":"","Mask":null}}]},"receiver":{"receiverList":[{"Regexp":{},"CIDR":{"IP":"","Mask":null}}]},"resource":{"-":{}},"conditions":{"conditionsTree":{"AND":[{"ANY":{"parentJsonpathAttribute":"jsonpath:$.spec.containers[:]","condition":{"condition":{"attribute":"jsonpath:$RELATIVE.securityContext.runAsUser","method":"EQ","value":"0"}}}},{"condition":{"attribute":"jsonpath:$.kind","method":"RE","value":"^Pod$"}}]}},"metadata":{"name":"runAsUser0"},"hash":"3d171b3db8380b7dc96dec48fc8f82fa","o":{},"-":true}`
		x := []byte(maplRuleJson)
		err = json.Unmarshal(x, &rule)
		So(err, ShouldEqual, nil)

		maplRuleJson2 := `{"ruleID":"1","sender":{"senderName":"*","senderType":"workload"},"receiver":{"receiverType":"hostname","receiverName":"google.com"},"protocol":"*","operation":"*","decision":"allow","conditions":[],"resource":null}`
		x = []byte(maplRuleJson2)
		err = json.Unmarshal(x, &rule)
		So(err, ShouldEqual, nil)

		//-----------------------
		maplRuleJson = `{"sender":{"senderName":"*"},"receiver":{"receiverName":"a_group:a2@d_group:d2","receiverType":"workload"},"protocol":"http","resource":{"resourceType":"path","resourceName":"/books/,/cars,*"},"operation":"*","conditions":{"conditionsTree":{"attribute":"encryptionType","method":"EQ","value":"tls"}},"decision":"allow"}`

		x = []byte(maplRuleJson)
		err = json.Unmarshal(x, &rule)
		if err != nil {
			fmt.Println(err)

		}

		maplRequestJson := `{"maplRule":{"sender":{"senderName":"*"},"receiver":{"receiverName":"a_group:a2@d_group:d2","receiverType":"workload"},"protocol":"http","resource":{"resourceType":"path","resourceName":"/books/,/cars,*"},"operation":"*","conditions":{"conditionsTree":{"attribute":"encryptionType","method":"EQ","value":"tls"}},"decision":"allow"},"account":"","origin":""}`

		//strval, err := json.Marshal(maplRequest)
		//if err != nil {
		//	log.Fatal(err)
		//}

		var ruleAndExtras RuleAndExtras
		err = json.Unmarshal([]byte(maplRequestJson), &ruleAndExtras)
		if err != nil {
			fmt.Println(err)

		}

	})
}

func TestJsonUnmarhshalWithPredefinedStrings(t *testing.T) {

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


		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_sender_translation.yaml", "../files/lists/predefined_string.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_receiver_translation.yaml", "../files/lists/predefined_string.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_sender_translation_list.yaml", "../files/lists/predefined_list.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_receiver_translation_list.yaml", "../files/lists/predefined_list.yaml")

		predefined_lists:=[]string{"../files/lists/predefined_list_workload.yaml","../files/lists/predefined_list_workload2.yaml","../files/lists/predefined_list_workload3.yaml"}
		for _,f:=range(predefined_lists) {
			testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_list.yaml", f)

		}
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo.yaml", "../files/lists/predefined_list_allowed_labels.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo2.yaml", "../files/lists/predefined_list_allowed_labels.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list.yaml", "../files/lists/predefined_list_allowed_labels.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_list2.yaml", "../files/lists/predefined_list_allowed_labels.yaml")

		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list.yaml", "../files/lists/predefined_list_allowed_labels.yaml")
		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rules_with_condition_translation_foo_regex_list2.yaml", "../files/lists/predefined_list_allowed_labels.yaml")

		testUnmarshalForOneFileWithPredefinedStrings("../files/rules/predefined_strings/rule_zooz.yaml","../files/lists/predefined_password_list.yaml")


	})
}


func testUnmarshalForOneFile(filename string) {

	var rulesYaml Rules
	var rulesJson Rules
	var rulesJsonUnmarshal1 Rules
	var rulesJsonUnmarshal2 Rules
	var rulesJson_deepcopy1 Rules
	var rulesJson_deepcopy2 Rules
	var rulesJson_deepcopy3 Rules
	var rulesJson_deepcopy4 Rules

	dataYaml, err := ioutil.ReadFile(filename)
	So(err, ShouldEqual, nil)
	dataJson, err := yaml.YAMLToJSON(dataYaml)
	So(err, ShouldEqual, nil)

	So(err, ShouldEqual, nil)
	err = yaml.Unmarshal(dataYaml, &rulesYaml)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson, &rulesJson)
	if err != nil {
		fmt.Println(filename)
	}

	dataJson2a, err := json.Marshal(rulesYaml)
	So(err, ShouldEqual, nil)
	dataJson2b, err := json.Marshal(rulesJson)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson2a, &rulesJsonUnmarshal1)
	So(err, ShouldEqual, nil)
	err = json.Unmarshal(dataJson2b, &rulesJsonUnmarshal2)
	So(err, ShouldEqual, nil)
	//---------------------------

	err = dc.Copy(&rulesJson_deepcopy1, &rulesYaml)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy2, &rulesJson)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy3, &rulesJsonUnmarshal1)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy4, &rulesJsonUnmarshal2)
	So(err, ShouldEqual, nil)

	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy3.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy4.Rules))

	hashes := []string{}

	for i, _ := range (rulesYaml.Rules) {
		hash1 := RuleMD5Hash(rulesYaml.Rules[i])
		hash2 := RuleMD5Hash(rulesJson.Rules[i])
		hash3 := RuleMD5Hash(rulesJsonUnmarshal1.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4.Rules[i])
		So(hash1, ShouldEqual, hash2)
		So(hash1, ShouldEqual, hash3)
		So(hash1, ShouldEqual, hash4)
		So(hash1, ShouldEqual, hash5)
		So(hash1, ShouldEqual, hash6)
		So(hash1, ShouldEqual, hash7)
		So(hash1, ShouldEqual, hash8)

		hashes = append(hashes, hash1)

	}

	//---------------------------
	// PrepareRulesWithPredefinedStrings
	//---------------------------

	err = PrepareRulesWithPredefinedStrings(&rulesYaml, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal1, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal2, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy1, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy2, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy3, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy4, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)

	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy3.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy4.Rules))

	So(len(rulesYaml.Rules), ShouldEqual, len(hashes))

	for i, _ := range (rulesYaml.Rules) {
		hash1 := RuleMD5Hash(rulesYaml.Rules[i])
		hash2 := RuleMD5Hash(rulesJson.Rules[i])
		hash3 := RuleMD5Hash(rulesJsonUnmarshal1.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4.Rules[i])
		So(hash1, ShouldEqual, hash2)
		So(hash1, ShouldEqual, hash3)
		So(hash1, ShouldEqual, hash4)
		So(hash1, ShouldEqual, hash5)
		So(hash1, ShouldEqual, hash6)
		So(hash1, ShouldEqual, hash7)
		So(hash1, ShouldEqual, hash8)

		So(hash1, ShouldEqual, hashes[i])

	}

	//------------------------------------------------------
	// now marshal/unmarshal after PrepareRulesWithPredefinedStrings
	//------------------------------------------------------

	var rulesJsonUnmarshal1B Rules
	var rulesJsonUnmarshal2B Rules
	var rulesJson_deepcopy1B Rules
	var rulesJson_deepcopy2B Rules
	var rulesJson_deepcopy3B Rules
	var rulesJson_deepcopy4B Rules

	dataJson3a, err := json.Marshal(rulesYaml)
	So(err, ShouldEqual, nil)
	dataJson3b, err := json.Marshal(rulesJson)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson3a, &rulesJsonUnmarshal1B)
	So(err, ShouldEqual, nil)
	err = json.Unmarshal(dataJson3b, &rulesJsonUnmarshal2B)
	So(err, ShouldEqual, nil)

	err = dc.Copy(&rulesJson_deepcopy1B, &rulesYaml)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy2B, &rulesJson)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy3B, &rulesJsonUnmarshal1B)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy4B, &rulesJsonUnmarshal2B)
	So(err, ShouldEqual, nil)

	So(len(rulesJson_deepcopy4B.Rules), ShouldEqual, len(hashes))

	for i, _ := range (rulesYaml.Rules) {

		hash3 := RuleMD5Hash(rulesJsonUnmarshal1B.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2B.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1B.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2B.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3B.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4B.Rules[i])

		So(hash3, ShouldEqual, hash4)
		So(hash3, ShouldEqual, hash5)
		So(hash3, ShouldEqual, hash6)
		So(hash3, ShouldEqual, hash7)
		So(hash3, ShouldEqual, hash8)

		So(hash3, ShouldEqual, hashes[i])

	}

	//---------------------------
	// PrepareRulesWithPredefinedStrings Again
	//---------------------------

	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal1B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal2B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy1B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy2B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy3B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy4B, PredefinedStringsAndLists{})
	So(err, ShouldEqual, nil)

	So(len(rulesJson_deepcopy4B.Rules), ShouldEqual, len(hashes))

	for i, _ := range (rulesYaml.Rules) {

		hash3 := RuleMD5Hash(rulesJsonUnmarshal1B.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2B.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1B.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2B.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3B.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4B.Rules[i])

		So(hash3, ShouldEqual, hash4)
		So(hash3, ShouldEqual, hash5)
		So(hash3, ShouldEqual, hash6)
		So(hash3, ShouldEqual, hash7)
		So(hash3, ShouldEqual, hash8)

		So(hash3, ShouldEqual, hashes[i])

	}

}

func testUnmarshalForOneFileWithPredefinedStrings(rulesFilename, stringsFilename string) {

	var rulesYaml Rules
	var rulesJson Rules
	var rulesJsonUnmarshal1 Rules
	var rulesJsonUnmarshal2 Rules
	var rulesJson_deepcopy1 Rules
	var rulesJson_deepcopy2 Rules
	var rulesJson_deepcopy3 Rules
	var rulesJson_deepcopy4 Rules


	predefinedStringsAndLists, err := YamlReadStringListsFromFile(stringsFilename)

	dataYaml, err := ioutil.ReadFile(rulesFilename)
	So(err, ShouldEqual, nil)
	dataJson, err := yaml.YAMLToJSON(dataYaml)
	So(err, ShouldEqual, nil)

	So(err, ShouldEqual, nil)
	err = yaml.Unmarshal(dataYaml, &rulesYaml)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson, &rulesJson)
	if err != nil {
		fmt.Println(rulesFilename)
	}

	dataJson2a, err := json.Marshal(rulesYaml)
	So(err, ShouldEqual, nil)
	dataJson2b, err := json.Marshal(rulesJson)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson2a, &rulesJsonUnmarshal1)
	So(err, ShouldEqual, nil)
	err = json.Unmarshal(dataJson2b, &rulesJsonUnmarshal2)
	So(err, ShouldEqual, nil)
	//---------------------------

	err = dc.Copy(&rulesJson_deepcopy1, &rulesYaml)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy2, &rulesJson)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy3, &rulesJsonUnmarshal1)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy4, &rulesJsonUnmarshal2)
	So(err, ShouldEqual, nil)

	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy3.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy4.Rules))

	//---------------------------
	// PrepareRulesWithPredefinedStrings
	//---------------------------

	err = PrepareRulesWithPredefinedStrings(&rulesYaml, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal1, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal2, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy1, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy2, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy3, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy4, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)

	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJsonUnmarshal2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy1.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy2.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy3.Rules))
	So(len(rulesYaml.Rules), ShouldEqual, len(rulesJson_deepcopy4.Rules))

	hashes := []string{}

	for i, _ := range (rulesYaml.Rules) {
		hash1 := RuleMD5Hash(rulesYaml.Rules[i])
		hash2 := RuleMD5Hash(rulesJson.Rules[i])
		hash3 := RuleMD5Hash(rulesJsonUnmarshal1.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4.Rules[i])
		So(hash1, ShouldEqual, hash2)
		So(hash1, ShouldEqual, hash3)
		So(hash1, ShouldEqual, hash4)
		So(hash1, ShouldEqual, hash5)
		So(hash1, ShouldEqual, hash6)
		So(hash1, ShouldEqual, hash7)
		So(hash1, ShouldEqual, hash8)

		hashes = append(hashes, hash1)

	}

	//------------------------------------------------------
	// now marshal/unmarshal after PrepareRulesWithPredefinedStrings
	//------------------------------------------------------

	var rulesJsonUnmarshal1B Rules
	var rulesJsonUnmarshal2B Rules
	var rulesJson_deepcopy1B Rules
	var rulesJson_deepcopy2B Rules
	var rulesJson_deepcopy3B Rules
	var rulesJson_deepcopy4B Rules

	dataJson3a, err := json.Marshal(rulesYaml)
	So(err, ShouldEqual, nil)
	dataJson3b, err := json.Marshal(rulesJson)
	So(err, ShouldEqual, nil)

	err = json.Unmarshal(dataJson3a, &rulesJsonUnmarshal1B)
	So(err, ShouldEqual, nil)
	err = json.Unmarshal(dataJson3b, &rulesJsonUnmarshal2B)
	So(err, ShouldEqual, nil)

	err = dc.Copy(&rulesJson_deepcopy1B, &rulesYaml)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy2B, &rulesJson)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy3B, &rulesJsonUnmarshal1B)
	So(err, ShouldEqual, nil)
	err = dc.Copy(&rulesJson_deepcopy4B, &rulesJsonUnmarshal2B)
	So(err, ShouldEqual, nil)

	So(len(rulesJson_deepcopy4B.Rules), ShouldEqual, len(hashes))

	for i, _ := range (rulesYaml.Rules) {

		hash3 := RuleMD5Hash(rulesJsonUnmarshal1B.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2B.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1B.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2B.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3B.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4B.Rules[i])

		So(hash3, ShouldEqual, hash4)
		So(hash3, ShouldEqual, hash5)
		So(hash3, ShouldEqual, hash6)
		So(hash3, ShouldEqual, hash7)
		So(hash3, ShouldEqual, hash8)

		So(hash3, ShouldEqual, hashes[i])

	}

	//---------------------------
	// PrepareRulesWithPredefinedStrings Again
	//---------------------------

	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal1B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJsonUnmarshal2B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy1B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy2B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy3B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)
	err = PrepareRulesWithPredefinedStrings(&rulesJson_deepcopy4B, predefinedStringsAndLists)
	So(err, ShouldEqual, nil)

	So(len(rulesJson_deepcopy4B.Rules), ShouldEqual, len(hashes))

	for i, _ := range (rulesYaml.Rules) {

		hash3 := RuleMD5Hash(rulesJsonUnmarshal1B.Rules[i])
		hash4 := RuleMD5Hash(rulesJsonUnmarshal2B.Rules[i])
		hash5 := RuleMD5Hash(rulesJson_deepcopy1B.Rules[i])
		hash6 := RuleMD5Hash(rulesJson_deepcopy2B.Rules[i])
		hash7 := RuleMD5Hash(rulesJson_deepcopy3B.Rules[i])
		hash8 := RuleMD5Hash(rulesJson_deepcopy4B.Rules[i])

		So(hash3, ShouldEqual, hash4)
		So(hash3, ShouldEqual, hash5)
		So(hash3, ShouldEqual, hash6)
		So(hash3, ShouldEqual, hash7)
		So(hash3, ShouldEqual, hash8)

		So(hash3, ShouldEqual, hashes[i])

	}

}
