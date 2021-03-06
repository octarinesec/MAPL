package MAPL_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/bhmj/jsonslice"
	jsonpath1 "github.com/oliveagle/jsonpath"
	jsonpath2 "github.com/yalp/jsonpath"
	"testing"
	"time"
)

var (
	PodRaw = []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "my-pod2",
    "labels": {
      "ben": "cool1",
      "app": "my-pod"
    }
  },
  "spec": {
    "containers": [
      {
        "image": "busybox",
        "command": [
          "sleep",
          "360000"
        ],
        "imagePullPolicy": "IfNotPresent",
        "name": "my-pod",
        "securityContext": {
          "privileged": true,
          "allowPrivilegeEscalation": false
        }
      }
    ],
    "restartPolicy": "Always"
  }
}
`)
)

var query1 = "$.spec.restartPolicy"
var query2 = "$.spec.containers[:]"
var query3 = "$.spec.containers[:].name"

func TestQueryPackages(t *testing.T) {

	testQuery(query1)
	testQuery(query2)
	testQuery(query3)

}
func testQuery(query string) {
	N := 10000

	var res []byte
	var err error
	var res2 interface{}
	var res3 interface{}
	var res4 interface{}
	var res5 interface{}
	var res5b interface{}

	t0 := time.Now()
	for i := 0; i < N; i++ {
		res, err = jsonslice.Get(PodRaw, query)
	}
	elapsed0 := time.Since(t0)
	fmt.Printf("elapsed jsonslice = %v\n", elapsed0)

	var PodObj interface{}
	json.Unmarshal(PodRaw, &PodObj)

	t1 := time.Now()
	for i := 0; i < N; i++ {
		if i%10 == 0 {
			json.Unmarshal(PodRaw, &PodObj)
		}
		res2, err = jsonpath1.JsonPathLookup(PodObj, query)
	}
	elapsed1 := time.Since(t1)
	fmt.Printf("elapsed oliveagle = %v\n", elapsed1)

	t2 := time.Now()
	for i := 0; i < N; i++ {
		if i%20 == 0 {
			json.Unmarshal(PodRaw, &PodObj)
		}
		res3, err = jsonpath2.Read(PodObj, query)

	}
	elapsed2 := time.Since(t2)
	fmt.Printf("elapsed yalp = %v\n", elapsed2)

	fastQuery, err := jsonpath2.Prepare(query)
	t2b := time.Now()
	for i := 0; i < N; i++ {
		if i%20 == 0 {
			json.Unmarshal(PodRaw, &PodObj)
		}
		res4, err = fastQuery(PodObj)

	}
	elapsed2b := time.Since(t2b)
	fmt.Printf("elapsed prepared yalp = %v\n", elapsed2b)

	t3 := time.Now()
	for i := 0; i < N; i++ {
		if i%20 == 0 {
			json.Unmarshal(PodRaw, &PodObj)
		}
		res5, err = jsonpath.Get(query, PodObj)

	}
	elapsed3 := time.Since(t3)
	fmt.Printf("elapsed PaesslerAG = %v\n", elapsed3)

	builder := gval.Full(jsonpath.PlaceholderExtension())
	fastQuery2, err := builder.NewEvaluable(query)

	t3b := time.Now()
	for i := 0; i < N; i++ {
		if i%20 == 0 {
			json.Unmarshal(PodRaw, &PodObj)
		}
		res5b, err = fastQuery2(context.Background(), PodObj)

	}
	elapsed3b := time.Since(t3b)
	fmt.Printf("elapsed prepared PaesslerAG = %v\n", elapsed3b)

	fmt.Println(string(res))
	fmt.Println(res2)
	fmt.Println(res3)
	fmt.Println(res4)
	fmt.Println(res5)
	fmt.Println(res5b)
	fmt.Printf("err=%v\n",err)
}
