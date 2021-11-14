package MAPL_engine

import (
	"encoding/json"
	"github.com/ghodss/yaml"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestAttributeConversion(t *testing.T) {

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

		inStr := `
		{"conditions" : 
			{"conditionsTree" : 
				{"AND" : [
							{
								"condition" : {
									"attribute" : "jsonpath:$.kind",
									"method" : "EQ",
									"value" : "Pod"
								}
							},
							{
								"condition" : {
									"attribute" : "jsonpath:$.spec.template.spec.containers[*].env[?(@.name=='http_proxy')].value",
									"method" : "EX",
									"value" : ""
								}
							},
							{
								"condition" : {
									"attribute" : "jsonpath:$.spec.template.spec.containers[*].env[?(@.name=='http_proxy')].value",
									"method" : "NEQ",
									"value" : "http://squid.doubleverify.prod:3128"
								}
							}
						]
				}
			}
		}`
		outStr,err := convertAttributesWithArraysToANYNode(inStr)
		So(err,ShouldBeNil)
		So(len(outStr), ShouldBeGreaterThan, 0)
	})
}


func TestInsertBracket(t *testing.T) {

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

		str1 := "asdsadf } asdasd }"
		str1out := insertTwoBrackets(str1)
		So(str1out, ShouldEqual, "asdsadf }}} asdasd }")


   		str2 := "{ asdsadf } asdasd } asdasd"
		str2out := insertTwoBrackets(str2)
		So(str2out, ShouldEqual, "{ asdsadf } asdasd }}} asdasd")

		str3 := "asdasd }"
		str3out := insertTwoBrackets(str3)
		So(str3out, ShouldEqual, "asdasd }}}")


		str4 := "asdasd "
		str4out := insertTwoBrackets(str4)
		So(str4out, ShouldEqual, "asdasd }}")


	})
}



func TestUnmarshalAfterConversions(t *testing.T) {

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

		filename := "../files/rules/main_fields/rules_operations.yaml" // no conditions
		testConversionOfOneFile(filename)
		filename = "../files/rules/with_conditions/rules_with_conditions.yaml" // non-jsonpath conditions
		testConversionOfOneFile(filename)
		filename = "../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_EQ.yaml" // with jsonpath condition
		testConversionOfOneFile(filename)
		filename = "../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_label_foofoo.yaml" // with jsonpath condition
		testConversionOfOneFile(filename)
		filename = "../files/rules/with_jsonpath_conditions_ALL_ANY_Multilevel/rules_with_jsonpath_conditions_multilevel_arrays.yaml" // with multilevel ANY/ALL
		testConversionOfOneFile(filename)
		filename = "../files/rules/with_return_value/rules_with_condition_keyword_and_return_value.yaml" // with return values
		testConversionOfOneFile(filename)
		filename = "../files/rules/array_in_attribute/rule_with_array_in_attribute.yaml" // with actual conversion
		testConversionOfOneFile(filename)
		filename = "../files/rules/array_in_attribute/rule_with_array_in_attribute_multilevel.yaml"  // with actual conversion
		testConversionOfOneFile(filename)


	})
}

func testConversionOfOneFile(filename string) {
	dataYaml, err := ioutil.ReadFile(filename)
	So(err, ShouldEqual, nil)
	dataJson, err := yaml.YAMLToJSON(dataYaml)
	So(err, ShouldEqual, nil)

	//------------
	// testing that conversions from MAPL v1 to MAPL v2 do not break the code:
	dataJson_with_conversion, err := convertAttributesWithArraysToANYNode(string(dataJson))
	So(err, ShouldEqual, nil)
	//------------
	var rulesJsonUnmarshal_with_conversion Rules
	err = json.Unmarshal([]byte(dataJson_with_conversion), &rulesJsonUnmarshal_with_conversion)
	So(err, ShouldEqual, nil)
}



func TestConversionsDebugging(t *testing.T) {

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

		c := ConditionsTree{}
		dataJson := `
		{"conditions" : 
			{"conditionsTree" : 
				{"AND" : [
							{
								"condition" : {
									"attribute" : "jsonpath:$.spec.template.spec.containers[*].env[?(@.name=='http_proxy')].value",
									"method" : "EX",
									"value" : ""
								}
							},
							{
								"condition" : {
									"attribute" : "jsonpath:$.spec.template.spec.containers[*].env[?(@.name=='http_proxy')].value",
									"method" : "NEQ",
									"value" : "http://squid.doubleverify.prod:3128"
								}
							}
						]
				}
			}
		}`
		err := json.Unmarshal([]byte(dataJson), &c)
		So(err, ShouldBeNil)
	})
}