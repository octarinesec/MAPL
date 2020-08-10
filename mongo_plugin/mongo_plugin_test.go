package mongo_plugin

import (
	"MAPL/MAPL_engine"
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/go-bongo/bongo"
	"github.com/globalsign/mgo/bson"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"io/ioutil"
	"log"

	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"github.com/ghodss/yaml"
	"math/rand"
)
/*
import (
"github.com/octarinesec/MAPL/MAPL_engine"
)*/

var testDir = "/tmp/octarine.testing"
const mongoPort = "33333"
var host = "127.0.0.1"
var DB = "plugin_test"
var collectionName = "raw_data"
var testIsDone = false

var mongoConnStr string
var mongoDbConnection *bongo.Connection
var mgoRefreshPeriod time.Duration

func init() {

	removeDir(testDir)
	os.MkdirAll(testDir, os.ModePerm)
	mongoDbDir:=testDir+"/mongodb"
	os.MkdirAll(mongoDbDir, os.ModePerm)
	stopMongodb()

	mongodPath:="/usr/bin/mongod"
	startMongodb(mongodPath, mongoDbDir, mongoPort)
	time.Sleep(time.Second * 5)

	connection, err := DbConnect(host,mongoPort,DB)
	if err != nil {
		log.Fatal(err)
	}
	mongoDbConnection = connection
	mgoRefreshPeriod = time.Duration(3) * time.Second



	// TODO - Find a better way of making sure the services are ready
	time.Sleep(time.Second * 1)


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

		results,_ := test_plugin("../files/rules/with_jsonpath_conditions/rules_with_jsonpath_conditions_GT.yaml",  "../files/raw_json_data/basic_jsonpath/json_raw_data1.json")
		So(results[0], ShouldEqual, true)


		fmt.Println("123")

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


func test_plugin(rulesFilename,jsonRawFilename string) ([]bool,error){


	rules, data, err := readRulesAndRawData(rulesFilename, jsonRawFilename)
	if err != nil {
		return []bool{}, err
	}
	fmt.Println(rules)
	id:= randomString(8)
	insertRawDataToMongo(id,data)

	/*
	outputResults := make([]bool, len(rules.Rules))
	for i_rule, rule := range (rules.Rules) {

		message.RequestJsonRaw = &data

		result := GetDataFromMongo(mongo_query)
		outputResults[i_rule] = result

	}
	return outputResults, nil
	*/

	deleteDocument(id)

	return []bool{}, nil
}

func readRulesAndRawData(rulesFilename,jsonRawFilename string) (MAPL_engine.RulesV2,[]byte,error) {

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

type testDoc struct{
	bongo.DocumentBase `bson:",inline"`
	ID string
	Raw interface{}
}

func insertRawDataToMongo(id string,data []byte)(error){

	var raw interface{}
	err:=json.Unmarshal(data,&raw)
	if err!=nil{
		return err
	}

	z := &testDoc{
		ID: id,
		Raw: raw,
	}
	err = mongoDbConnection.Collection(collectionName).Save(z)

	return err

}


func deleteDocument(id string)(error){


	err := mongoDbConnection.Collection(collectionName).DeleteOne(bson.M{"id":id})
	return err

}



func DbConnect(Host,Port,DB string) (*bongo.Connection, error) {


	var connStr string

		connStr = fmt.Sprintf("%v:%v/%v", Host, Port, DB)


		log.Println("Connecting to DB without TLS")

		dbconfig := &bongo.Config{
			ConnectionString: connStr,
			Database:         DB,
		}
		conn, err := bongo.Connect(dbconfig)
		if err == nil {
			conn.Session.SetMode(mgo.Strong, true)
		}

		return conn, err

}

func randomString(length int) string {

	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ" +
		"abcdefghijklmnopqrstuvwxyzåäö" +
		"0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	str := b.String() // E.g. "ExcbsVQs"
	return str
}