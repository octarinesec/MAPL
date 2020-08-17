package mongo_plugin

import (
	"MAPL/MAPL_engine"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/globalsign/mgo"
	//"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/globalsign/mgo/bson"

	//bson2 "go.mongodb.org/mongo-driver/bson"
	//"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/go-bongo/bongo"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"

	"github.com/ghodss/yaml"
	"context"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

/*
import (
"github.com/octarinesec/MAPL/MAPL_engine"
)*/

var testDir = "/tmp/octarine.testing"
var mongodPath = "/usr/bin/mongod"

const mongoPort = "33333"

var host = "127.0.0.1"
var DB = "plugin_test"
var collectionName = "raw_data"
var testIsDone = false

var mongoConnStr string
var mongoDbConnection *bongo.Connection
var mgoRefreshPeriod time.Duration

var mongoCtx2 context.Context
var mongoDbConnection2 *mongo.Database
var mongoDbCollection2 *mongo.Collection

type connectionStruct struct {
	connection *bongo.Connection
	err        error
}

func init() {

	removeDir(testDir)
	os.MkdirAll(testDir, os.ModePerm)
	mongoDbDir := testDir + "/mongodb"
	os.MkdirAll(mongoDbDir, os.ModePerm)

	// this is to use a timeout and retry connection to mongo if it fails
	resp := make(chan connectionStruct, 1)
	flag := false
	z := connectionStruct{}
	z.err = errors.New("error")

	for i := 0; i <= 3; i++ {

		if flag {
			break
		}
		go func() {
			connection, err := restartMongo(mongoDbDir)
			resp <- connectionStruct{connection: connection, err: err}
		}()

		// Listen on our channel AND a timeout channel - which ever happens first.
		select {
		case res := <-resp:
			fmt.Println(res)
			z.connection = res.connection
			z.err = res.err
			flag = true
		case <-time.After(5 * time.Second):
			fmt.Println("out of time...")
			time.Sleep(time.Second * 2)
		}
	}

	connection := z.connection
	err := z.err

	if err != nil {
		log.Fatal(err)
	}
	mongoDbConnection = connection
	mgoRefreshPeriod = time.Duration(3) * time.Second

	// TODO - Find a better way of making sure the services are ready
	time.Sleep(time.Second * 1)



	mongoCtx2, _ = context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(mongoCtx2, options.Client().ApplyURI(fmt.Sprintf("mongodb://%v:%v",host,mongoPort)))
	if err != nil {
		panic(err)
	}
	//defer client.Disconnect(mongoCtx2)

	mongoDbConnection2 = client.Database(DB)
	mongoDbCollection2 = mongoDbConnection2.Collection(collectionName)

}

func restartMongo(mongoDbDir string) (*bongo.Connection, error) {
	stopMongodb()
	startMongodb(mongodPath, mongoDbDir, mongoPort)
	time.Sleep(time.Second * 5)
	connection, err := DbConnect(host, mongoPort, DB)
	return connection, err
}

func startMongodb(mongodPath string, dbpath string, port string) {
	log.Printf("Starting mongodb at %v on port %v", dbpath, port)
	cmd := exec.Command(mongodPath,
		"--logappend",
		fmt.Sprintf("--logpath=%v/log", dbpath),
		fmt.Sprintf("--dbpath=%v", dbpath),
		fmt.Sprintf("--port=%v", port))

	err := cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start mongod: %v", err)
	}
	log.Println("Started mongod")
}
func stopMongodb() {
	killTcp4Process("mongod", mongoPort)
}

func removeDir(dir string) {
	if len(dir) == 0 || !strings.HasPrefix(dir, "/tmp") {
		log.Fatalf("Refusing to remove test dir '%v'", dir)
	} else {
		log.Printf("Removing %v", dir)
		err := os.RemoveAll(dir)
		if err != nil {
			log.Fatalf("Failed to remove test dir '%v'", dir)
		}
	}
}

func killTcp4Process(name string, port string) {
	cmd := exec.Command("netstat", "-nlp")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Start()
	re, err := regexp.Compile(fmt.Sprintf(".*0.0.0.0:%v.*LISTEN +([0-9]+)/%v", port, name))
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 0 {
			pid, err := strconv.Atoi(matches[1])
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Killing test %v process (%v)", name, pid)
			proc, err := os.FindProcess(pid)
			if err != nil {
				log.Fatal(err)
			}
			proc.Kill()
		}
	}
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
		results, _ := test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_GE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LT_4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_LE_2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual, false)

		// string equality:
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo3.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo4.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false)

		// existence:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_EX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_replicas.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_replicas_NEX.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_replicas.json")
		So(results[0], ShouldEqual, true)

		// regex:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar2.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar3.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_RE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_label_foo_ar2_NRE.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_foo_bar4.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

		// IN/NIN:

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

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
		results, _ := test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json")
		So(results[0], ShouldEqual, false)
		// OR:
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_OR.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json")
		So(results[0], ShouldEqual, false)
		// NOT:
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json")
		So(results[0], ShouldEqual, true)

		//Multilevel
		// NOT-AND
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_NOT_AND.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json")
		So(results[0], ShouldEqual, true)

		//AND-NOT
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar_replicas_5.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/and_or_not/rules_with_jsonpath_conditions_AND_NOT.yaml", "../files/raw_json_data/mongo_plugin/and_or_not/json_raw_data_foo_bar2_replicas_5.json")
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

		// ANY:
		results, _ := test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ANY.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_B.json")
		So(results[0], ShouldEqual, false)

		// ALL:
		results, _ = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_B.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/any_all/rules_with_jsonpath_conditions_LT_and_LT_spec_containers_ALL.yaml", "../files/raw_json_data/mongo_plugin/any_all/json_raw_data_2containers_C.json")
		So(results[0], ShouldEqual, true)

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

		results, _ := test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key1.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value1.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_AND.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_AND2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)

		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND2.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_value_AND3.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		So(results[0], ShouldEqual, true)


		results, err := test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_json.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		strErr:=fmt.Sprintf("%v",err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "json VALUE is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_relative.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		strErr=fmt.Sprintf("%v",err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "VALUE within array is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_value_relative_ALL.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		strErr=fmt.Sprintf("%v",err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "VALUE within array is not supported")

		results, err = test_plugin("../files/rules/mongo_plugin/key_value/rules_with_jsonpath_conditions_key_relative.yaml", "../files/raw_json_data/key_value/json_raw_data_labels.json")
		strErr=fmt.Sprintf("%v",err)
		fmt.Println(strErr)
		So(strErr, ShouldEqual, "KEY within array is not supported")

	})
}

/*
func TestMongoPluginNumberConversion(t *testing.T) {

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


		q:=bson.M{"_id":"mongosum","value" : bson.JavaScript{Code: "function (x,y) { return x+y;}",	} }
		err := mongoDbConnection.Collection("system.js").Collection().Insert(q)
		fmt.Println(err)
		// now in mongo:
		// > db.system.js.find()
		// > db.eval("mongosum(1,2)")
		// WARNING: db.eval is deprecated
		// 3

		q=bson.M{"_id":"convertNumberString","value" : bson.JavaScript{Code: functionConvertNumberString ,	} }
		err = mongoDbConnection.Collection("system.js").Collection().Insert(q)
		fmt.Println(err)
		// >  db.eval("convertNumberString('500m')")
		// WARNING: db.eval is deprecated
		// 0.5
		// > db.eval("convertNumberString('2Gi')")
	    // WARNING: db.eval is deprecated
		// 2147483648

		results, _ := test_plugin("../files/rules/mongo_plugin/number_suffix/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/number_suffix/json_raw_data_number.json")
		So(results[0], ShouldEqual, true)

		// numbers with m,K,Ki,M,Mi suffixes etc...:
		results, _ = test_plugin("../files/rules/mongo_plugin/number_suffix/rules_with_jsonpath_conditions_EQ.yaml", "../files/raw_json_data/mongo_plugin/number_suffix/json_raw_data_number_with_suffix.json")
		So(results[0], ShouldEqual, true)

	})
}


func mongoNow() bson.JavaScript {

	return bson.JavaScript{
		Code: "(new Date()).ISODate('YYYY-MM-DD hh:mm:ss')",
	}
}

func MongoSum() bson.JavaScript {

	return bson.JavaScript{
		Code: "function (x,y) { return x+y;}",
	}
}
*/

func TestMain(m *testing.M) {
	testIsDone = false
	testResult := m.Run()
	testIsDone = true

	time.Sleep(time.Second * 1)

	stopMongodb()

	os.Exit(testResult)
}

func test_plugin(rulesFilename, jsonRawFilename string) ([]bool, error) {

	rules, data, err := readRulesAndRawData(rulesFilename, jsonRawFilename)
	if err != nil {
		return []bool{}, err
	}

	id := randomString(16)
	insertRawDataToMongo(id, data)

	outputResults := make([]bool, len(rules.Rules))
	for i_rule, rule := range (rules.Rules) {

		query, added_pipeline,err := rule.Conditions.ConditionsTree.ToMongoQuery("")
		if err!=nil{
			return []bool{}, err
		}
		fmt.Println(added_pipeline)

		query_pipeline:=append(added_pipeline,bson.M{"$match":query} )
		//query_pipeline:=[]bson.M{bson.M{"$match":query}}

		if err != nil {
			return []bool{}, err
		}

		z, _ := json.Marshal(query)
		fmt.Println(string(z))
		z2, _ := json.Marshal(query_pipeline)
		fmt.Println(string(z2))

		result := getDataFromMongo(query) // query
		result2 := getDataFromMongoAggregate(query_pipeline) // aggregation pipeline


		if len(added_pipeline)==0 {
			if result != result2 {
				return []bool{}, err
			}
			outputResults[i_rule] = result
		}else{
			outputResults[i_rule] = result2
		}


	}

	err = deleteDocument(id)
	if err != nil {
		return []bool{}, err
	}
	return outputResults, nil
}

func readRulesAndRawData(rulesFilename, jsonRawFilename string) (MAPL_engine.RulesV2, []byte, error) {

	rules, err := MAPL_engine.YamlReadRulesFromFileV2(rulesFilename)
	if err != nil {
		fmt.Printf("error: %v", err)
		return MAPL_engine.RulesV2{}, []byte{}, err
	}

	data, err := MAPL_engine.ReadBinaryFile(jsonRawFilename)
	if err != nil {
		fmt.Printf("can't read json raw file")
		return MAPL_engine.RulesV2{}, []byte{}, err
	}
	isYaml := strings.HasSuffix(jsonRawFilename, ".yaml")
	if isYaml {
		data2, err := yaml.YAMLToJSON(data)
		if err != nil {
			return MAPL_engine.RulesV2{}, []byte{}, err
		}
		data = data2
	}

	return rules, data, nil
}

type testDoc struct {
	bongo.DocumentBase `bson:",inline"`
	ID                 string
	Raw                interface{}
}

func insertRawDataToMongo(id string, data []byte) (error) {

	var raw interface{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	z := &testDoc{
		ID:  id,
		Raw: raw,
	}
	err = mongoDbConnection.Collection(collectionName).Save(z)

	return err

}

func deleteDocument(id string) (error) {

	err := mongoDbConnection.Collection(collectionName).DeleteOne(bson.M{"id": id})
	return err

}

func getDataFromMongo(query bson.M) bool {

	results := mongoDbConnection.Collection(collectionName).Find(query)
	var item interface{}
	counter := 0
	for results.Next(&item) {
		counter += 1
	}
	return counter > 0
}

func getDataFromMongoAggregate(query_pipeline []bson.M) bool {


	results,err := mongoDbCollection2.Aggregate(mongoCtx2,query_pipeline)
	if err!=nil{
		return false
	}

	var items []bson.M
	results.All(mongoCtx2,&items)

	return len(items) > 0
}



func DbConnect(Host, Port, DB string) (*bongo.Connection, error) {

	var connStr string

	connStr = fmt.Sprintf("%v:%v/%v", Host, Port, DB)

	log.Println("Connecting to DB")

	//dialInfo := mgo.DialInfo{}
	//dialInfo.Timeout = time.Duration(10 * time.Second)

	dbconfig := &bongo.Config{
		ConnectionString: connStr,
		Database:         DB,
		//DialInfo:         &dialInfo,
	}

	conn, err := bongo.Connect(dbconfig)
	if err == nil {
		conn.Session.SetMode(mgo.Strong, true)

	}
	return conn, err

}

func mongoConvertNumberString() bson.JavaScript {

	return bson.JavaScript{Code: functionConvertNumberString}
}

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

/* javascript code:


db.system.js.save({_id: "convertNumberString",
                  value: function convertNumberString(inputString) {

    var strVec = ["e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"];
    var factorVec = [1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, Math.pow(1024, 2), Math.pow(1024, 3), Math.pow(1024, 4), Math.pow(1024, 5), Math.pow(1024, 6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001];

    var outputString = inputString;
    var i;
    var factor=1.0;
    for (i = 0; i < strVec.length; i++) {

        var unit = strVec[i];
        var f = factorVec[i];

        var flag1 = inputString.endsWith(unit);
        var flag2 = false;
        if (flag1) {
            var count = (inputString.match(unit) || []).length;
            flag2 = (count == 1);
        }
        if (flag1 && flag2) {
            outputString = inputString.replace(unit, "");
            factor=f;
            break;
        }
    }

    return Number(outputString)*factor;

}
})


db.eval("return convertNumberString(500m);");


 */
/*
var functionConvertNumberString = `function (inputString) {

var strVec = ["e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"];
var factorVec = [1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, Math.pow(1024, 2), Math.pow(1024, 3), Math.pow(1024, 4), Math.pow(1024, 5), Math.pow(1024, 6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001];

var outputString = inputString;
var i;
var factor=1.0;
for (i = 0; i < strVec.length; i++) {

var unit = strVec[i];
var f = factorVec[i];

var flag1 = inputString.endsWith(unit);
var flag2 = false;
if (flag1) {
var count = (inputString.match(unit) || []).length;
flag2 = (count == 1);
}
if (flag1 && flag2) {
outputString = inputString.replace(unit, "");
factor=f;
break;
}
}

return Number(outputString)*factor;

}
})`
*/
var functionConvertNumberString = `function (inputString) {var strVec = ["e3", "e6", "e9", "e12", "e15", "e18", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "K", "M", "G", "T", "P", "E", "m"];var factorVec = [1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1024, Math.pow(1024, 2), Math.pow(1024, 3), Math.pow(1024, 4), Math.pow(1024, 5), Math.pow(1024, 6), 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 0.001];var outputString = inputString;var i;var factor=1.0;for (i = 0; i < strVec.length; i++) {var unit = strVec[i];var f = factorVec[i];var flag1 = inputString.endsWith(unit);var flag2 = false;if (flag1) {var count = (inputString.match(unit) || []).length;flag2 = (count == 1);}if (flag1 && flag2) {outputString = inputString.replace(unit, "");factor=f;break;}} return Number(outputString)*factor;}`

// key val:
// db.products.insert({    "name" : "AAA",         "quantity" : 4,         "price" : 3.5 ,"md":{"a":"b","c":"d"}})
// db.products.insert({    "name" : "BBB",         "quantity" : 2,         "price" : 5.5 ,"md":{"x":"b","y":"z"}})
// db.products.insert({    "name" : "CCC",         "quantity" : 1,         "price" : 5.5 ,"arr":[{"md":{"x":"b","y":"z"}},{"md":{"A":"A","B":"B"}}]})
// db.products.aggregate({$addFields: {     array: {$objectToArray: '$md'}  }},  {$match: {'array.v': 'b',price:{$lt:5}}})
