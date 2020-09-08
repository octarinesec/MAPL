package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
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

		testUnmarshalForOneFile("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_annotations_EQ.yaml")

		testUnmarshalForOneFile("../files/rules/with_conditions/rules_with_conditions.yaml")

		var files []string
		var roots []string

		main_root := "../files/rules"

		err := filepath.Walk(main_root, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				roots = append(roots, path)
			}
			return nil
		})
		if err != nil {
			panic(err)
		}

		for _, root := range (roots) {
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if !info.IsDir() {
					if !strings.Contains(path,"invalid_rule") {
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

func testUnmarshalForOneFile(filename string) {

	dataYaml, err := ioutil.ReadFile(filename)
	So(err, ShouldEqual,nil)
	dataJson, err := yaml.YAMLToJSON(dataYaml)
	So(err, ShouldEqual,nil)


	rules := Rules{}
	err = json.Unmarshal(dataJson, &rules)
	if err!=nil{
		fmt.Println(filename)
	}
	So(err, ShouldEqual,nil)
	rules2 := Rules{}
	err = yaml.Unmarshal(dataYaml, &rules2)
	So(err, ShouldEqual,nil)

	//-----------------------------------
	dataJson2, err := json.Marshal(rules)
	So(err, ShouldEqual,nil)
	rules3 := Rules{}
	err = json.Unmarshal(dataJson2, &rules3)
	So(err, ShouldEqual,nil)
	//---------------------------
	for i, _ := range (rules.Rules) {
		hash1 := RuleMD5Hash(rules.Rules[i])
		hash2 := RuleMD5Hash(rules2.Rules[i])
		hash3 := RuleMD5Hash(rules2.Rules[i])
		So(hash1, ShouldEqual, hash2)
		So(hash1, ShouldEqual, hash3)
	}

}
