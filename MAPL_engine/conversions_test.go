package MAPL_engine

import (
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