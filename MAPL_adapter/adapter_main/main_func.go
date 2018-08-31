// main adapter packcage
package main

import (
	"os"

	"istio.io/istio/mixer/adapter/MAPL_adapter"
	"strings"
	"strconv"
	"log"
)

// main is called at the adapters start-up. the global parameters MAPL_adapter.Params are first initialized and then MAPL_adapter.NewMaplAdapter is created.
func main() {
	port := ""
	rulesFilename := "rules.yaml"
	if len(os.Args) > 1 {
		port = os.Args[1]
        log.Println("port=",port)
		rulesFilename = os.Args[2]
        log.Println("rulesFilename=",rulesFilename)
	}
	setParms()
	MAPL_adapter.Params.RulesFileName = rulesFilename

	log.Println("params=",MAPL_adapter.Params)

	s, err := MAPL_adapter.NewMaplAdapter(port,MAPL_adapter.Params.RulesFileName)
	if err != nil {
		log.Printf("unable to start server: %v", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

// read parameters from environment variables
func setParms(){

	/*for _, pair := range os.Environ() {
		log.Println(pair)
	}*/

	MAPL_adapter.Params.Logging = false
	if strings.EqualFold(os.Getenv("LOGGING"),"true") {
		MAPL_adapter.Params.Logging = true
	}

	MAPL_adapter.Params.CacheTimeoutSecs = 30 // default
	cacheTimeoutSecs, err := strconv.Atoi(os.Getenv("CACHE_TIMEOUT_SECS"))
	log.Println("CACHE_TIMEOUT_SECS=",os.Getenv("CACHE_TIMEOUT_SECS"),cacheTimeoutSecs)
	if err==nil{
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