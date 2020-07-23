package MAPL_engine

import (
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestBET(t *testing.T) {

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

		rules, err := YamlReadRulesFromFile("../examples_v2/rules_basic_v1.yaml")
		So(err, ShouldEqual, nil)
		condition := rules.Rules[0].DNFConditions[0].ANDConditions[0]

		messages, err := YamlReadMessagesFromFile("../examples/messages_basic_sender_name.yaml")
		So(err, ShouldEqual, nil)
		message := messages.Messages[0]

		t1 := And{[]Node{True{}, True{}}}
		t1Eval := t1.Eval(&message) // returns true
		So(t1Eval, ShouldEqual, true)

		t2 := Or{[]Node{False{}, True{}}}
		t2Eval := t2.Eval(&message) // returns true
		So(t2Eval, ShouldEqual, true)

		node1 := And{[]Node{True{}, True{}, True{}}}
		node2 := Or{[]Node{False{}, True{}, &node1}}
		node3 := And{[]Node{condition}}
		node := And{[]Node{&node1, &node2, True{}, &node3}}
		nodeEval := node.Eval(&message) // returns true
		So(nodeEval, ShouldEqual, true)

	})
}


func TestBET2(t *testing.T) {

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

		rules, err := YamlReadRulesFromFileV2("../examples_v2/rules_basic_v2b.yaml")
		So(err, ShouldEqual, nil)
		condString:="((<jsonpath:$.kind-EQ-Deployment> || (<jsonpath:$.abc-EQ-ABC> && <jsonpath:$.def-EQ-DEF>)) && (<jsonpath:$.zzz-EQ-ZZZ> && <jsonpath:$.xyz-EQ-XYZ>))"
		So(rules.Rules[0].ConditionsTree.String2(),ShouldEqual,condString)

		rules, err = YamlReadRulesFromFileV2("../examples_v2/rules_basic_v2c.yaml")
		errStr:=fmt.Sprintf("%v",err)
		So(errStr, ShouldEqual, "node type not supported. possible error: array of conditions without AND,OR (etc) parent")


		rules, err = YamlReadRulesFromFileV2("../examples_v2/rules_basic_v2d.yaml")
		errStr=fmt.Sprintf("%v",err)
		expectedError:=`yaml: unmarshal errors:
  line 20: key "attribute" already set in map
  line 21: key "method" already set in map
  line 22: key "value" already set in map`
		So(errStr, ShouldEqual, expectedError)
		*/
		_, err := YamlReadRulesFromFileV2("../examples_v2/rules_basic_v2e.yaml")
		So(err, ShouldEqual, "node type not supported. possible error: array of conditions without AND,OR (etc) parent")




	})
}