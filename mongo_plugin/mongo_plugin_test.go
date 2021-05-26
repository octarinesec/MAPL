package mongo_plugin

import (
	"encoding/json"
	"fmt"

	"github.com/octarinesec/MAPL/MAPL_engine"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"

	"context"
	"github.com/ghodss/yaml"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var mongodPath = "/usr/bin/mongod"

const mongoPort = 56789

var host = "127.0.0.1"
var dbName = "plugin_test"
var collectionName = "raw_data"
var testIsDone = false

var mongoConnStr string

var mongoCtx context.Context
var mongoClient *mongo.Client
var mongoDbConnection *mongo.Database
var mongoDbCollection *mongo.Collection

type connectionStruct struct {
	connection *mongo.Database
	ctx        context.Context
	client     *mongo.Client
	err        error
}

func init() {

	os.Setenv("TEST", "true")

	err := restartMongo()
	if err != nil {
		log.Fatal(err)
	}

	client, err := DbConnect(host, mongoPort)

	if err == nil {
		fmt.Println("Connected to MongoDB!")
	} else {
		panic(err)
	}

	mongoDbConnection = client.Database(dbName)
	mongoDbCollection = mongoDbConnection.Collection(collectionName)

}

func restartMongo() error {

	stopMongodb()
	//err := restartMongodb()
	//if err != nil {
	err := startMongodb(mongoPort)
	if err != nil {
		return err
	}

	time.Sleep(time.Second * 1)
	return nil

}

func startMongodb(port int) error {
	// docker run --name mongodb_for_test -d -p 127.0.0.1:33333:27017 mongo
	log.Printf("Starting mongodb at on port %v", port)
	cmd := exec.Command("docker", "run", "--name", "mongodb_for_tests", "-d", "-p", fmt.Sprintf("%v:27017", port), "mongo", "--bind_ip_all", "--replSet", "rs0")
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		log.Printf("%s\n", stdoutStderr)
	}

	if err == nil {
		log.Println("Started mongod")
	}

	time.Sleep(5 * time.Second)
	cmd = exec.Command("docker", "exec", "-i", "mongodb_for_tests", "mongo", "--eval", "rs.initiate()")
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		log.Printf("%s\n", stdoutStderr)
	}

	cmd = exec.Command("docker", "exec", "-i", "mongodb_for_tests", "mongo", "--eval", "rs.status()")
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
		log.Printf("%s\n", stdoutStderr)
	}

	return err
}

func stopMongodb() {
	stopContainer("mongodb_for_tests")
}

func stopContainer(container string) {

	cmd := exec.Command("docker", "kill", container)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	}
	log.Printf("%s\n", stdoutStderr)

	cmd = exec.Command("docker", "container", "rm", container) // we remove the container to remove the data (until i find a better way to just delete a mounted folder in windows)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	}
	log.Printf("%s\n", stdoutStderr)
	log.Printf("stopped %v", container)
}

func TestStartLocalMongo(t *testing.T) {
	Convey("TestStartLocalMongo", t, func() {

		id := randomString(16)
		data := []byte(`{"a":"b","c":{"d":"e"}}`)
		err := insertRawDataToMongo(id, collectionName, data)

		So(err, ShouldEqual, nil)

	})
}

func TestMongoPluginDebugging(t *testing.T) {

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

		// numbers:
		results, _ := test_plugin("../files/rules/debugging/rules_with_jsonpath_debug_with_array_index.yaml", "../files/raw_json_data/debugging/json_raw_data_debug_with_array_index_1.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/debugging/rules_with_jsonpath_debug_with_array_index.yaml", "../files/raw_json_data/debugging/json_raw_data_debug_with_array_index_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/debugging/rules_with_jsonpath_debug_with_array_index.yaml", "../files/raw_json_data/debugging/json_raw_data_debug_with_array_index_3.json", "raw")
		So(results[0], ShouldEqual, false)

	})
}

func TestMongoPluginBasic(t *testing.T) {

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

		// numbers:
		results, _ := test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)

		// string equality:
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false)

		// existence:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_replicas.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_replicas.json", "raw")
		So(results[0], ShouldEqual, true)

		// regex:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json", "raw")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json", "raw")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

		// IN/NIN:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json", "raw")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

	})
}

func TestMongoPluginPrefix(t *testing.T) {

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

		// numbers:
		results, _ := test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "raw2")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "raw2")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ_raw_prefix.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json", "")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ_raw_prefix.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json", "")
		So(results[0], ShouldEqual, true)

	})
}

func TestMongoPluginAndOrNot(t *testing.T) {

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

		// AND:
		results, _ := test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)
		// OR:
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)
		// NOT:
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)

		//Multilevel
		// NOT-AND
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)

		//AND-NOT
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json", "raw")
		So(results[0], ShouldEqual, false)

		//AND-OR

	})
}

func TestMongoPluginAnyAll(t *testing.T) {

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

		// invalid ANY:
		results, err := test_plugin("../files/rules/mongo_plugin/any_all/invalid_rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		errString := fmt.Sprintf("%v", err)
		So(errString, ShouldEqual, "deepscan is not supported")
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/invalid_rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY2.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		errString = fmt.Sprintf("%v", err)
		So(errString, ShouldEqual, "list of ParentJsonpathAttributes is not supported yet")
		// invalid ALL:
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/invalid_rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		errString = fmt.Sprintf("%v", err)
		So(errString, ShouldEqual, "deepscan is not supported")
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/invalid_rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL2.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		errString = fmt.Sprintf("%v", err)
		So(errString, ShouldEqual, "list of ParentJsonpathAttributes is not supported yet")
		// ANY:
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		So(results[0], ShouldEqual, true)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_B.json", "raw")
		So(results[0], ShouldEqual, false)

		// ALL:
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json", "raw")
		So(results[0], ShouldEqual, false)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_B.json", "raw")
		So(results[0], ShouldEqual, false)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_C.json", "raw")
		So(results[0], ShouldEqual, true)

		// Multi-level:
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json", "raw")
		So(results[0], ShouldEqual, false)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json", "raw")
		So(results[0], ShouldEqual, true)

		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json", "raw")
		So(results[0], ShouldEqual, true)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays2.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json", "raw")
		So(results[0], ShouldEqual, true)

		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts.json", "raw")
		So(results[0], ShouldEqual, false)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B.json", "raw")
		So(results[0], ShouldEqual, false)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_B2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, err = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_multilevel_arrays3.yaml", "../files/raw_json_data/multilevel_any_all/json_raw_data_2containers_2volumeMounts_C.json", "raw")
		So(results[0], ShouldEqual, false)

	})
}

func TestMongoPluginKeyValue(t *testing.T) {

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

		results, _ := test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key1.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value1.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_AND.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_AND2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json", "raw")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json", "raw")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json4.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json", "raw")
		So(results[0], ShouldEqual, true)

		results, err := test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json5.yaml", "../files/raw_json_data/key_value/json_raw_data_labels_relative.json", "raw")
		strErr := fmt.Sprintf("%v", err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "VALUE within array is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/invalid_rules_with_jsonpath_conditions_key_json.yaml", "../files/raw_json_data/key_value/json_raw_data_labels2.json", "raw")
		strErr = fmt.Sprintf("%v", err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "jsonpath condition $KEY must not have a subfield [jsonpath:$KEY.def2]")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_relative.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		fmt.Println(results)
		strErr = fmt.Sprintf("%v", err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "VALUE within array is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_relative_ALL.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		strErr = fmt.Sprintf("%v", err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "VALUE within array is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_relative.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json", "raw")
		strErr = fmt.Sprintf("%v", err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "KEY within array is not supported")

	})
}

func test_plugin(rulesFilename, jsonRawFilename, prefix string) ([]bool, error) {

	rules, data, err := readRulesAndRawData(rulesFilename, jsonRawFilename)
	if err != nil {
		return []bool{}, err
	}

	testReadWriteRules(rules)

	id := randomString(16)
	collectionName := randomString(16) // random collection name or else the test will fail if they are run in parallel
	insertRawDataToMongo(id, collectionName, data)

	outputResults := make([]bool, len(rules.Rules))
	for i_rule, rule := range (rules.Rules) {

		// ------------------------------
		// from rule (this is the main way)
		resultQuery, err := rule.ToMongoQuery(prefix)
		resultQueryFromRule := false
		if resultQuery.Type == MAPL_engine.QueryTypeAggregate {
			q := resultQuery.Query.([]bson.M)
			resultQueryFromRule = getDataFromMongoAggregate(q, collectionName)
		}
		if resultQuery.Type == MAPL_engine.QueryTypeSimple {
			q := resultQuery.Query.(bson.M)
			resultQueryFromRule = getDataFromMongo(q, collectionName)
			z, _ := json.Marshal(q)
			fmt.Println(string(z))
		}

		// -------------------------------
		// directly from conditions:
		// just for unit tests
		r := rule.GetPreparedRule()
		query, added_pipeline, err := r.Conditions.ConditionsTree.ToMongoQuery(prefix, "", 0)

		if err != nil {
			deleteDocument(id, collectionName)
			return []bool{}, err
		}
		fmt.Println(added_pipeline)

		query_pipeline := append(added_pipeline, bson.M{"$match": query})
		//query_pipeline:=[]bson.M{bson.M{"$match":query}}

		if err != nil {
			deleteDocument(id, collectionName)
			return []bool{}, err
		}

		z, _ := json.Marshal(query)
		fmt.Println(string(z))
		z2, _ := json.Marshal(query_pipeline)
		fmt.Println(string(z2))

		resultSimpleQueryFromConditions := getDataFromMongo(query, collectionName)                      // query
		resultAggregateQueryFromConditions := getDataFromMongoAggregate(query_pipeline, collectionName) // aggregation pipeline

		if len(added_pipeline) == 0 {
			if resultSimpleQueryFromConditions != resultAggregateQueryFromConditions {
				deleteDocument(id, collectionName)
				return []bool{}, err
			}
			So(resultQueryFromRule, ShouldEqual, resultSimpleQueryFromConditions)
			outputResults[i_rule] = resultSimpleQueryFromConditions
		} else {
			So(resultQueryFromRule, ShouldEqual, resultAggregateQueryFromConditions)
			outputResults[i_rule] = resultAggregateQueryFromConditions
		}

	}

	err = deleteDocument(id, collectionName)
	if err != nil {
		return []bool{}, err
	}
	return outputResults, nil
}

func readRulesAndRawData(rulesFilename, jsonRawFilename string) (MAPL_engine.Rules, []byte, error) {

	rules, err := MAPL_engine.YamlReadRulesFromFile(rulesFilename)
	if err != nil {
		fmt.Printf("error: %v", err)
		return MAPL_engine.Rules{}, []byte{}, err
	}

	data, err := MAPL_engine.ReadBinaryFile(jsonRawFilename)
	if err != nil {
		fmt.Printf("can't read json raw file")
		return MAPL_engine.Rules{}, []byte{}, err
	}
	isYaml := strings.HasSuffix(jsonRawFilename, ".yaml")
	if isYaml {
		data2, err := yaml.YAMLToJSON(data)
		if err != nil {
			return MAPL_engine.Rules{}, []byte{}, err
		}
		data = data2
	}

	return rules, data, nil
}

type testDoc struct {
	ID  string
	Raw interface{}
}

func insertRawDataToMongo(id, collectionName string, data []byte) (error) {

	var raw interface{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	z := &testDoc{
		ID:  id,
		Raw: raw,
	}
	_, err = mongoDbConnection.Collection(collectionName).InsertOne(nil, z)

	return err

}

type ruleDoc struct {
	ID   string
	Rule MAPL_engine.Rule
}

func testReadWriteRules(rules MAPL_engine.Rules) (error) {

	for _, rule := range rules.Rules {

		id := randomString(16)
		z := &ruleDoc{
			ID:   id,
			Rule: rule,
		}
		_, err := mongoDbConnection.Collection("ruleCollection").InsertOne(nil, z)
		if err != nil {
			return err
		}

		var rule2 ruleDoc
		cursor := mongoDbConnection.Collection("ruleCollection").FindOne(nil, bson.M{"id": id})
		err = cursor.Decode(&rule2)
		if err != nil {
			return err
		}

		h1 := MAPL_engine.RuleMD5Hash(rule)
		h2 := MAPL_engine.RuleMD5Hash(rule2.Rule)
		So(h1, ShouldEqual, h2)

		_, err = mongoDbConnection.Collection("ruleCollection").DeleteMany(nil, bson.M{"id": id})

		if err != nil {
			return err
		}

	}
	return nil

}

func deleteDocument(id string, collectionName string) (error) {

	_, err := mongoDbConnection.Collection(collectionName).DeleteOne(nil, bson.M{"id": id})
	return err

}

func getDataFromMongo(query bson.M, collectionName string) bool {

	results, err := mongoDbConnection.Collection(collectionName).Find(nil, query)
	if err != nil {
		return false
	}

	var items []bson.M
	results.All(mongoCtx, &items)
	return len(items) > 0
}

func getDataFromMongoAggregate(query_pipeline []bson.M, collectionName string) bool {

	results, err := mongoDbConnection.Collection(collectionName).Aggregate(nil, query_pipeline)
	if err != nil {
		return false
	}

	var items []bson.M
	results.All(mongoCtx, &items)

	return len(items) > 0
}

func DbConnect(host string, port int) (*mongo.Client, error) {

	// Set client options
	connectionString := fmt.Sprintf("mongodb://%v:%v//?connect=direct", host, port)
	clientOptions := options.Client().ApplyURI(connectionString)

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}
	return client, err
}

/*
func DbConnect_old(host, port, DB string) (*mongo.Database, context.Context, *mongo.Client, error) {

	client, err := mongo.NewClient(options.Client().SetConnectTimeout(time.Duration(10 * time.Second)).ApplyURI(fmt.Sprintf("mongodb://%v:%v", host, port)))
	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	//defer client.Disconnect(ctx) // we disconnect outside, when all the tests are finished

	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		// Can't connect to Mongo server
		log.Fatal(err)
	}

	connection := client.Database(DB)
	return connection, ctx, client, nil

}
*/
func randomString(length int) string {

	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	str := b.String() // E.g. "ExcbsVQs"
	return str
}

func TestMain(m *testing.M) {
	testIsDone = false
	testResult := m.Run()
	testIsDone = true

	time.Sleep(time.Second * 1)

	stopMongodb()

	os.Exit(testResult)
}
