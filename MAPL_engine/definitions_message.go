package MAPL_engine

import (
	"encoding/json"
	"net"
)

//-------------------messages-------------------------------------
// MessageAttributes structure contains message attributes checked with the rules.
// The attributes were taken from Istio's HTTP message attributes [https://istio.io/docs/reference/config/policy-and-telemetry/attribute-vocabulary/]
type MessageAttributes struct {
	//--------------------------------------------------
	// taken from Istio (retained only the ones we actually use)
	SourceIp        string `yaml:"sender_ip,omitempty"`        //   Client IP address  example: 10.0.0.117
	SourceNamespace string `yaml:"sender_namespace,omitempty"` //  Source workload instance namespace. example: my-namespace
	SourceCluster   string `yaml:"sender_cluster,omitempty"`   //  Source workload instance cluster. example: aws:edo

	DestinationIp        string `yaml:"receiver_ip,omitempty"`        //  Server IP address. example: 10.0.0.104
	DestinationPort      string `yaml:"receiver_port,omitempty"`      //  The recipient port on the server IP address. example: 8080
	DestinationNamespace string `yaml:"receiver_namespace,omitempty"` //  Destination workload instance namespace. example: istio-system
	DestinationCluster   string `yaml:"receiver_cluster,omitempty"`   //  Destination workload instance cluster. example: aws:edo

	RequestPath      string `yaml:"request_path,omitempty"`       //  The HTTP URL path including query string
	RequestHost      string `yaml:"request_host,omitempty"`       //  HTTP/1.x host header or HTTP/2 authority header. Example: redis-master:3337
	RequestMethod    string `yaml:"request_method,omitempty"`     //  The HTTP method.
	RequestSize      int64  `yaml:"request_size,omitempty"`       //  Size of the request in bytes.For HTTP requests this is equivalent to the Content-Length header.
	RequestTime      string `yaml:"request_time,omitempty"`       //  The timestamp when the destination receives the request.This should be equivalent to Firebase “now”. [https://firebase.google.com/docs/reference/android/com/google/firebase/Timestamp]
	RequestUseragent string `yaml:"request_user_agent,omitempty"` //  The HTTP User-Agent header.

	ContextProtocol string `yaml:"request_protocol,omitempty"` //  Protocol of the request or connection being proxied. example: tcp
	// -----------------------------------------------
	// The following are general attributes (not from Istio):
	MessageID string `yaml:"message_id,omitempty"`

	SourceService      string `yaml:"sender_service,omitempty"`   //  The service identifier
	DestinationService string `yaml:"receiver_service,omitempty"` //  The fully qualified name of the service that the server belongs to.my-svc.my-namespace

	SourceLabelsJson      string `yaml:"sender_labels,omitempty"`   //  The sender service labels
	DestinationLabelsJson string `yaml:"receiver_labels,omitempty"` //  The receiver service labels

	ContextType string `yaml:"request_type,omitempty"` // type of context in relation to the ContextProtocol.
	// examples:
	// for ContextProtocol HTTP  ContextType=path
	// for ContextProtocol=KAFKA  ContextType=kafkaTopic or consumerGroup

	EncryptionType    string   `yaml:"encryption_type,omitempty"`
	EncryptionVersion *float64 `yaml:"encryption_version,omitempty"`

	RequestJsonRaw              *[]byte      `yaml:"json_raw,omitempty"`
	RequestJsonRawRelative      *[]byte      `yaml:"json_raw_relative,omitempty"`
	RequestRawInterface         *interface{} `yaml:"interface_raw,omitempty"`
	RequestRawInterfaceRelative *interface{} `yaml:"interface_raw_relative,omitempty"`
	Domain                      string       `yaml:"domain,omitempty"`

	RequestTimeSecondsFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp // used for debuggin in units tests
	RequestTimeMinutesFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp // used for debuggin in units tests
	RequestTimeHoursFromMidnightUTC   float64 `yaml:"-"` // conversion of RequestTime timestamp // used for debuggin in units tests

	SourceNetIp      net.IP `yaml:"-"`
	DestinationNetIp net.IP `yaml:"-"`

	SourceLabels      map[string]string `yaml:"-"`
	DestinationLabels map[string]string `yaml:"-"`
}

// Messages structure contains a list of messages
type Messages struct {
	Messages []MessageAttributes `yaml:"messages,omitempty"`
}

// ToJson converts a structure into a json string
func (messageAttributes MessageAttributes) ToJson() (string, error) { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(messageAttributes, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// ToJson converts a structure into a json string
func (messages Messages) ToJson() (string, error) { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(messages, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
