package MAPL_engine

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestConditionsTree(t *testing.T) {

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

		rules, err := YamlReadRulesFromFile("../files/rules/basic_rules/rules_basic_v1.yaml")
		So(err, ShouldEqual, nil)
		condition := rules.Rules[0].DNFConditions[0].ANDConditions[0]

		messages, err := YamlReadMessagesFromFile("../files/messages/main_fields/messages_basic_sender_name.yaml")
		So(err, ShouldEqual, nil)
		message := messages.Messages[0]

		t1 := And{[]Node{True{}, True{}}}
		t1Eval, _ := t1.Eval(&message) // returns true
		So(t1Eval, ShouldEqual, true)

		t2 := Or{[]Node{False{}, True{}}}
		t2Eval, _ := t2.Eval(&message) // returns true
		So(t2Eval, ShouldEqual, true)

		node1 := And{[]Node{True{}, True{}, True{}}}
		node2 := Or{[]Node{False{}, True{}, &node1}}
		node3 := And{[]Node{&condition}}
		node := And{[]Node{&node1, &node2, True{}, &node3}}
		nodeEval, _ := node.Eval(&message) // returns true
		So(nodeEval, ShouldEqual, true)

	})
}

func TestConditionsTree2(t *testing.T) {

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

		rules, err := YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2a.yaml")
		So(err, ShouldEqual, nil)
		condString := "<jsonpath:$.kind-EQ-Deployment>"
		So(rules.Rules[0].Conditions.ConditionsTree.String(), ShouldEqual, condString)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2aa.yaml")
		So(err, ShouldEqual, nil)
		condString = "(<jsonpath:$.abc-EQ-ABC> && <jsonpath:$.kind-EQ-Deployment>)"
		So(rules.Rules[0].Conditions.ConditionsTree.String(), ShouldEqual, condString)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2b.yaml")
		So(err, ShouldEqual, nil)
		condString = "(((<jsonpath:$.abc-EQ-ABC> && <jsonpath:$.def-EQ-DEF>) || <jsonpath:$.kind-EQ-Deployment>) && (<jsonpath:$.xyz-EQ-XYZ> && <jsonpath:$.zzz-EQ-ZZZ>))"
		So(rules.Rules[0].Conditions.ConditionsTree.String(), ShouldEqual, condString)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2c.yaml")
		errStr := fmt.Sprintf("%v", err)
		So(errStr, ShouldEqual, "node type not supported. possible error: array of conditions without AND,OR (etc) parent")

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2d.yaml")
		errStr = fmt.Sprintf("%v", err)
		expectedError := `yaml: unmarshal errors:
  line 20: key "attribute" already set in map
  line 21: key "method" already set in map
  line 22: key "value" already set in map`
		So(errStr, ShouldEqual, expectedError)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2e0.yaml")
		So(err, ShouldEqual, nil)
		condStringExpected := "<jsonpath:$.abc-EQ-ABC>"
		condString = rules.Rules[0].Conditions.ConditionsTree.String()
		So(condString, ShouldEqual, condStringExpected)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2e1.yaml")
		errStr = fmt.Sprintf("%v", err)
		So(errStr, ShouldEqual, "node type not supported. possible error: array of conditions without AND,OR (etc) parent")

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2e2.yaml")
		So(err, ShouldEqual, nil)
		condStringExpected = "<jsonpath:$.abc-EQ-ABC>"
		condString = rules.Rules[0].Conditions.ConditionsTree.String()
		So(condString, ShouldEqual, condStringExpected)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2e3.yaml")
		So(err, ShouldEqual, nil)
		condString = rules.Rules[0].Conditions.ConditionsTree.String()
		So(condString, ShouldEqual, condStringExpected)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2f.yaml")
		So(err, ShouldEqual, nil)
		condString = "[ANY<jsonpath:$.spec.template.spec.containers[:]>:<jsonpath:$.abc-EQ-ABC>]"
		So(rules.Rules[0].Conditions.ConditionsTree.String(), ShouldEqual, condString)

		rules, err = YamlReadRulesFromFileV2("../files/rules/basic_rules/rules_basic_v2fb.yaml")
		So(err, ShouldEqual, nil)
		condString = "[ANY<jsonpath:$.spec.template.spec.containers[:]>:((<jsonpath:$.b-EQ-B> || <jsonpath:$.c-EQ-C>) && <jsonpath:$.a-EQ-A>)]"
		So(rules.Rules[0].Conditions.ConditionsTree.String(), ShouldEqual, condString)

	})
}
