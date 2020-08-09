package mongo_plugin

import (
	"bufio"
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/go-bongo/bongo"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/smartystreets/goconvey/convey/reporting"
	"golang.octarinesec.com/common"

	"io/ioutil"
	"log"

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
const mongoPort = "33333"
var host = "127.0.0.1"
var DB = "plugin_test"

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

	retryCount := 2
	retrySeconds := 2
	common.SetRetry(retryCount, retrySeconds)

	connection.

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

		fmt.Println("123")

	})
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