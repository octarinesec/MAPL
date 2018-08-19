// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"istio.io/istio/mixer/adapter/MAPL_adapter"
	"strings"
	"strconv"
)

func main() {
	port := ""
	rulesFilename := "rules.yaml"
	if len(os.Args) > 1 {
		port = os.Args[1]
        fmt.Println("port=",port)
		rulesFilename = os.Args[2]
        fmt.Println("rulesFilename=",rulesFilename)
	}
	setParms()
	MAPL_adapter.Params.RulesFileName = rulesFilename

	fmt.Println(MAPL_adapter.Params)

	s, err := MAPL_adapter.NewMaplAdapter(port,MAPL_adapter.Params.RulesFileName)
	if err != nil {
		fmt.Printf("unable to start server: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

func setParms(){
	// set global variables from environment variables:

	MAPL_adapter.Params.Logging = false
	if strings.EqualFold(os.Getenv("LOGGING"),"true") {
		MAPL_adapter.Params.Logging = true
	}

	MAPL_adapter.Params.CacheTimeoutSecs = 30 // default
	cacheTimeoutSecs, err := strconv.Atoi(os.Getenv("CACHE_TIMEOUT_SECS"))
	if err!=nil{
		MAPL_adapter.Params.CacheTimeoutSecs=cacheTimeoutSecs
	}
	switch(os.Getenv("ISTIO_TO_SERVICE_NAME_CONVENTION")){
	case(MAPL_adapter.IstioToServicenameConventionString[MAPL_adapter.IstioUid]):
		MAPL_adapter.Params.IstioToServiceNameConvention = MAPL_adapter.IstioUid
	case(MAPL_adapter.IstioToServicenameConventionString[MAPL_adapter.IstioWorkloadAndNamespace]):
		MAPL_adapter.Params.IstioToServiceNameConvention = MAPL_adapter.IstioWorkloadAndNamespace
	default:
		MAPL_adapter.Params.IstioToServiceNameConvention = MAPL_adapter.IstioUid // default
	}

	//MAPL_adapter.Params.RulesFileName = os.Getenv("RULES_FILE_NAME")

}