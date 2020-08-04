package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"
)

// YamlReadMessageAttributes function reads message attributes from a yaml string
func YamlReadMessageAttributes(yamlString string) (MessageAttributes, error) {

	var messageAttributes MessageAttributes
	err := yaml.Unmarshal([]byte(yamlString), &messageAttributes)
	if err != nil {
		log.Printf("error: %v", err)
		return MessageAttributes{}, err
	}
	//fmt.Printf("---values found:\n%+v\n\n", rule)

	flag, outputString, err := IsNumberOfFieldsEqual(messageAttributes, yamlString)
	if err != nil {
		return MessageAttributes{}, err
	}
	if flag == false {
		return MessageAttributes{}, fmt.Errorf("number of fields in rules does not match number of fields in yaml file:\n" + outputString)
	}

	AddResourceType(&messageAttributes)

	return messageAttributes, nil
}

// YamlReadMessagesFromString function reads messages from a yaml string
func YamlReadMessagesFromString(yamlString string) (Messages, error) {

	var messages Messages
	err := yaml.Unmarshal([]byte(yamlString), &messages)
	if err != nil {
		log.Printf("error: %v", err)
		return Messages{}, err
	}

	addResourceTypeToMessages(&messages)
	err = addTimeInfoToMessages(&messages)
	if err != nil {
		return Messages{}, err
	}
	AddNetIpToMessages(&messages)
	parseLabelsJsonOfMessages(&messages)

	/*
	flag, outputString, err := IsNumberOfFieldsEqual(messages, yamlString)
	if err != nil {
		return Messages{}, err
	}
	if flag == false {
		err_str := "number of fields in rules does not match number of fields in yaml file:\n" + outputString
		log.Printf("error: %s", err_str)
		return Messages{}, fmt.Errorf(err_str)
	}
	 */
	return messages, nil
}

// YamlReadMessagesFromFile function reads messages from file
func YamlReadMessagesFromFile(filename string) (Messages, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("error: %v", err)
		return Messages{}, err
	}
	messages, err := YamlReadMessagesFromString(string(data))
	if err != nil {
		log.Printf("error: %v", err)
		return Messages{}, err
	}
	return messages, nil
}


// YamlReadMessagesFromString function reads messages from a yaml string
func YamlReadStringListsFromString(yamlString string) (PredefinedStringsAndLists, error) {

	var predefinedStringsAndLists PredefinedStringsAndLists
	err := yaml.Unmarshal([]byte(yamlString), &predefinedStringsAndLists)
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}

	return predefinedStringsAndLists, nil
}

func YamlReadStringListsFromFile(filename string) (PredefinedStringsAndLists, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}
	predefinedStringsAndLists, err := YamlReadStringListsFromString(string(data))
	if err != nil {
		log.Printf("error: %v", err)
		return PredefinedStringsAndLists{}, err
	}
	return predefinedStringsAndLists, nil
}



// AddResourceType function adds resource type to one message by the resource protocol for HTTP and TCP. For KAFKA the resource_type need to be filled in the message attributes.
func AddResourceType(message *MessageAttributes) {
	// add resource_type by the resource_protocol
	// we have resource_type to allow for several types per one protocol.
	//
	message.ContextType = ""
	switch message.ContextProtocol { // these are the only protocols we currently support
	case "HTTP", "http":
		message.ContextType = "path"
	case "TCP", "tcp":
		message.ContextType = "port"
	}
}

// addResourceTypeToMessages function adds resource type to all messages
func addResourceTypeToMessages(messages *Messages) {
	// add resource_type by the resource_protocol
	// we have resource_type to allow for several types per one protocol.

	for i, _ := range messages.Messages {
		AddResourceType(&messages.Messages[i])
	}
}

// AddTimeInfoToMessage function parses timestamp data in one message and extract the second, minutes and hours since midnight.
func AddTimeInfoToMessage(message *MessageAttributes) error {
	//
	// extract timestamp info
	//

	//t, err := time.Parse(time.RFC3339,"2018-07-29T14:30:00-07:00")
	t, err := time.Parse(time.RFC3339, message.RequestTime)

	if err != nil {
		log.Printf("error: %v", err)
		return err
	}

	nanosecondsFromMidnight := float64(((t.Hour()*60+t.Minute())*60+t.Second())*1e9 + t.Nanosecond())

	message.RequestTimeSecondsFromMidnightUTC = nanosecondsFromMidnight / 1e9
	message.RequestTimeMinutesFromMidnightUTC = nanosecondsFromMidnight / 1e9 / 60
	message.RequestTimeHoursFromMidnightUTC = nanosecondsFromMidnight / 1e9 / 60 / 60

	message.RequestTimeMinutesParity = (int64(message.RequestTimeMinutesFromMidnightUTC) % 60) % 2

	return nil
}

// addTimeInfoToMessages function parses timestamp data for all messages
func addTimeInfoToMessages(messages *Messages) error {
	// add resource_type by the resource_protocol
	// we have resource_type to allow for several types per one protocol.

	for i, _ := range messages.Messages {
		err := AddTimeInfoToMessage(&messages.Messages[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// AddNetIpToMessage converts string ips to type net.IP
func AddNetIpToMessage(message *MessageAttributes) {
	message.SourceNetIp = net.ParseIP(message.SourceIp)
	message.DestinationNetIp = net.ParseIP(message.DestinationIp)
}

// addNetIpToMessages function parses string ip data for all messages
func AddNetIpToMessages(messages *Messages) {
	for i, _ := range messages.Messages {
		AddNetIpToMessage(&messages.Messages[i])
	}
}

// parseLabelsJsonOfMessage converts json string of labels to map[string]string
func parseLabelsJsonOfMessage(message *MessageAttributes) {

	/*
		str:="{key1:abc,key2:def ,key3 : xyz}"
		str=addQuotesToJsonString(str)
		z:=make(map[string]string)
		json.Unmarshal([]byte(str),&z)
		fmt.Println(z)
	*/

	str := addQuotesToJsonString(message.SourceLabelsJson)
	json.Unmarshal([]byte(str), &message.SourceLabels)

	str = addQuotesToJsonString(message.DestinationLabelsJson)
	json.Unmarshal([]byte(str), &message.DestinationLabels)

}

func parseLabelsJsonOfMessages(messages *Messages) {
	for i, _ := range messages.Messages {
		parseLabelsJsonOfMessage(&messages.Messages[i])
	}
}

func addQuotesToJsonString(json_string string) (out_string string) {
	out_string = json_string
	out_string = strings.Replace(out_string, " ", "", -1)
	out_string = strings.Replace(out_string, "{", "{\"", -1)
	out_string = strings.Replace(out_string, ",", "\",\"", -1)
	out_string = strings.Replace(out_string, ":", "\":\"", -1)
	out_string = strings.Replace(out_string, "}", "\"}", -1)
	return out_string
}
