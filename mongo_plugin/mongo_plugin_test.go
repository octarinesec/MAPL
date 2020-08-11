package mongo_plugin

import (
	"MAPL/MAPL_engine"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-bongo/bongo"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"

	"github.com/ghodss/yaml"
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

func TestMongoPlugin(t *testing.T) {

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
		So(results[0], ShouldEqual,true )

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_2.json")
		So(results[0], ShouldEqual, false)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_EQ2.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_replicas_5.json")
		So(results[0], ShouldEqual,true )

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
		So(results[0], ShouldEqual,true )
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_IN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json")
		So(results[0], ShouldEqual, false)

		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_sts.json")
		So(results[0], ShouldEqual, true)
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_dep.json")
		So(results[0], ShouldEqual,false )
		results, _ = test_plugin("../files/rules/mongo_plugin/rules_with_jsonpath_conditions_NIN.yaml", "../files/raw_json_data/mongo_plugin/json_raw_data_no_kind.json")
		So(results[0], ShouldEqual, false) // if the field doesn't exist we return false

	})
}

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

		query, err := rule.Conditions.ConditionsTree.ToMongoQuery()
		if err != nil {
			return []bool{}, err
		}
		result := getDataFromMongo(query)
		outputResults[i_rule] = result

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

	//query=bson.M{}
	//query["raw.spec.replicas"]=5

	results := mongoDbConnection.Collection(collectionName).Find(query)
	var item interface{}
	counter := 0
	for results.Next(&item) {
		counter += 1
	}
	return counter > 0
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
