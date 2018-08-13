# MAPL Engine

## Overview
The MAPL Engine is a go library that provides functionality to parse and verify rules written in MAPL
as described in the
[MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).

## Installation
```shell
go get -u -v github.com/octarinesec/MAPL
```

## Use of the Engine 

* The main functionality of the Engine is the check function:
```go
result, msg, _, _, _ := MAPL_engine.Check(&message, &rules)
```

* The Engine provides ability to read MAPL rules from yaml files:
```go
rules := MAPL_engine.YamlReadRulesFromFile(rulesFilename)
```

* The Check function uses regular expressions in order to support wildcards and lists as described in the MAPL specifications. 
Therefore, after reading the rules from the input file, the relevant fields are converted to regular expressions using `convertStringToRegex` and `convertOperationStringToRegex` functions. 


* The Engine provides ability to read message attributes from yaml files (for testing purposes):
```
messages := MAPL_engine.YamlReadMessagesFromFile(messagesFilename)
```
* After reading the messages from the input file, some fields are parsed and added as message attributes (for example, 
`requestTimeHoursFromMidnightUTC` is extracted from `message.RequestTime`).
When message attributes are created by a different method (for example, getting the attributes from a seperate process as in the [Istio mixer adapter](isnert link here)) attention is needed to parse and add them in that process. 

* one-attribute-conditions are tested in `testOneCondition` function. The value to compare is extracted there from the message attributes.
For example in the case of "payloadSize"
```
valueToCompareInt = message.RequestSize
```
The list of supported message attributes to be used in the conditions is given in
[Supported Attributes](https://github.com/octarinesec/MAPL/tree/master/docs/SUPPORTED_ATTRIBUTES.md) document.


## Data Structures

The rules and message attributes data structures are defined in [definitions.go](./definitions.go)

## Examples
See examples of use in [test_check.go](./tests/test_check.go)  
Examples of input rules and messages are in the [examples folder](./examples)
