package MAPL_engine

import (
	"regexp"
	"encoding/json"
	"time"
	"net"
)

type GeneralStruct interface { // a general interface to structures.
	ToJson() string // This function is used when comparing structures read from yaml files to the resulting fields in the structure.
}

//-------------------rules-------------------------------------

// Resource structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Resource struct {
	/* Examples:
	HTTP:httpPath:<http_path_name>,
	kafka:kafkaTopic:<kafka_topic_name>
	kafka:consumerGroup:<consumer_group_name>
	TCP:port:<port number>
	*/
	ResourceProtocol string `yaml:"resourceProtocol,omitempty"`
	ResourceType     string `yaml:"resourceType,omitempty"`
	ResourceName     string `yaml:"resourceName,omitempty"`
	ResourceNameRegex *regexp.Regexp `yaml:"-"`
}
// Condition structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Condition struct {
	Attribute string `yaml:"attribute,omitempty"`
	Method    string `yaml:"method,omitempty"`
	Value     string `yaml:"value,omitempty"`
	ValueInt int64 `yaml:"-"`
	ValueFloat float64 `yaml:"-"`
	ValueRegex *regexp.Regexp `yaml:"-"`
	ValueStringRegex *regexp.Regexp `yaml:"-"`

	AttributeIsSenderLabel bool `yaml:"-"`
	AttributeSenderLabelKey string `yaml:"-"`
	AttributeIsReceiverLabel bool `yaml:"-"`
	AttributeReceiverLabelKey string `yaml:"-"`
	ValueIsReceiverLabel bool `yaml:"-"`
	ValueReceiverLabelKey string `yaml:"-"`

}

// ANDConditions structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type ANDConditions struct {
	ANDConditions []Condition `yaml:"ANDconditions,omitempty"`
}
// Rule structure - as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Rule struct {
	// rule syntax:
	//	<sender, receiver, resource, operation> : <conditions> : <decision>
	//
	RuleID        string          `yaml:"rule_id,omitempty"`
	Sender        string          `yaml:"sender,omitempty"`
	Receiver      string          `yaml:"receiver,omitempty"`
	Resource      Resource        `yaml:"resource,omitempty"`
	Operation     string          `yaml:"operation,omitempty"`
	DNFConditions []ANDConditions `yaml:"DNFconditions,omitempty"`
	Decision      string          `yaml:"decision,omitempty"`

	OperationRegex *regexp.Regexp `yaml:"-"`

	SenderList []ExpandedSenderReceiver `yaml:"-"`
	ReceiverList []ExpandedSenderReceiver `yaml:"-"`
}
// Rules structure contains a list of rules
type Rules struct {
	Rules []Rule `yaml:"rules,omitempty"`
}
//
type ExpandedSenderReceiver struct {
	Name string
	Regexp *regexp.Regexp
	IsIP bool
	IsCIDR bool
	CIDR net.IPNet
	IP net.IP
}

// ToJson converts a structure into a json string
func (rule Rule) ToJson() string {  // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		panic("error converting to json")
	}
	return (string(jsonBytes))
}
// ToJson converts a structure into a json string
func (rules Rules) ToJson() string { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		panic("error converting to json")
	}
	return (string(jsonBytes))
}
//-------------------messages-------------------------------------

// MessageAttributes structure contains message attributes checked with the rules.
// The attributes were taken from Istio's HTTP message attributes [https://istio.io/docs/reference/config/policy-and-telemetry/attribute-vocabulary/]
type MessageAttributes struct {
	//--------------------------------------------------

	SourceUid string  `yaml:"sender_uid,omitempty"`//  Platform-specific unique identifier for the client instance of the source service. example: kubernetes: //redis-master-2353460263-1ecey.my-namespace
	SourceIp string  `yaml:"sender_ip,omitempty"` //   Client IP address  example: 10.0.0.117
	SourceName string  `yaml:"sender_name,omitempty"`//  Source workload instance name. example: redis-master-2353460263-1ecey
	SourceNamespace string  `yaml:"sender_namespace,omitempty"`//  Source workload instance namespace. example: my-namespace
	SourcePrincipal string  `yaml:"sender_principal,omitempty"`//  Authority under which the source workload instance is running. example: service-account-foo
	SourceOwner  string  `yaml:"sender_owner,omitempty"`//  Reference to the workload controlling the source workload instance.	example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-policy
	SourceWorkloadUid  string `yaml:"sender_workload_uid,omitempty"`//  Unique identifier of the source workload.  example: istio://istio-system/workloads/istio-policy
	SourceWorkloadName  string  `yaml:"sender_workload_name,omitempty"`//  Source workload name. example: istio-policy
	SourceWorkloadNamespace  string  `yaml:"sender_workload_namespace,omitempty"`//  Source workload namespace.	example: istio-system

	// remark in kuberentes the SourceWorkloadName with the SourceWorkloadNamespace may uniquely identify the service
	// whereas the SourceName may identify a specific instance of the workload

	DestinationUid    string  `yaml:"receiver_uid,omitempty"`//  Platform-specific unique identifier for the server instance of the destination service. example: kubernetes://my-svc-234443-5sffe.my-namespace
	DestinationIp  string  `yaml:"receiver_ip,omitempty"`//  Server IP address. example: 10.0.0.104
	DestinationPort  string  `yaml:"receiver_port,omitempty"`//  The recipient port on the server IP address. example: 8080
	DestinationName  string  `yaml:"receiver_name,omitempty"`//  Destination workload instance name. example: istio-telemetry-2359333
	DestinationNamespace  string  `yaml:"receiver_namespace,omitempty"`//  Destination workload instance namespace. example: istio-system
	DestinationPrincipal  string  `yaml:"receiver_principal,omitempty"`//  Authority under which the destination workload instance is running. example: service-account
	DestinationOwner  string  `yaml:"receiver_owner,omitempty"`//  Reference to the workload controlling the destination workload instance. example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-telemetry
	DestinationWorkloadUid  string  `yaml:"receiver_workload_uid,omitempty"`//  Unique identifier of the destination workload. example: istio://istio-system/workloads/istio-telemetry
	DestinationWorkloadName  string  `yaml:"receiver_workload_name,omitempty"`//  Destination workload name. example: iistio-telemetry
	DestinationWorkloadNamespace  string  `yaml:"receiver_workload_namespace,omitempty"`//  Destination workload namespace. example: istio-system

	RequestPath    string  `yaml:"request_path,omitempty"`//  The HTTP URL path including query string
	RequestHost    string  `yaml:"request_host,omitempty"`//  HTTP/1.x host header or HTTP/2 authority header. Example: redis-master:3337
	RequestMethod    string  `yaml:"request_method,omitempty"`//  The HTTP method.
	RequestScheme    string  `yaml:"request_uri,omitempty"`//  URI Scheme of the request
	RequestSize  int64  `yaml:"request_size,omitempty"`//  Size of the request in bytes.For HTTP requests this is equivalent to the Content-Length header.
	RequestTotalSize  int64  `yaml:"request_total_size,omitempty"`//  Total size of HTTP request in bytes, including request headers, body and trailers.
	RequestTime  string  `yaml:"request_time,omitempty"`//  The timestamp when the destination receives the request.This should be equivalent to Firebase “now”. [https://firebase.google.com/docs/reference/android/com/google/firebase/Timestamp]
	RequestUseragent  string  `yaml:"request_user_agent,omitempty"`//  The HTTP User-Agent header.


	ResponseSize  int64  `yaml:"response_size,omitempty"`//  Size of the response body in bytes
	ResponseTotalSize  int64 `yaml:"response_total_size,omitempty"`//  Total size of HTTP response in bytes, including response headers and body.
	ResponseTime  string `yaml:"response_time,omitempty"`//  The timestamp when the destination produced the response.
	ResponseDuration  time.Duration `yaml:"response_duration,omitempty"`//  duration    The amount of time the response took to generate.
	ResponseCode  int64 `yaml:"response_code,omitempty"`//  The response’s HTTP status code.
	ResponseGrpcStatus  string `yaml:"response_grpc_status,omitempty"`//  The response’s gRPC status
	ResponseGrpcMessage  string `yaml:"response_grpc_message,omitempty"`//  The response’s gRPC status message.

	ConnectionMtls  string  `yaml:"connection_mtls,omitempty"`//  Indicates whether a request is received over a mutual TLS enabled downstream connection.
	ConnectionRequestedServerName  string  `yaml:"connection_requested_server_name,omitempty"`// The requested server name (SNI) of the connection

	ContextProtocol  string  `yaml:"request_protocol,omitempty"`//  Protocol of the request or connection being proxied. example: tcp
	// -----------------------------------------------
	// The following are general attributes:
	MessageID string `yaml:"message_id,omitempty"`

	SourceService string  `yaml:"sender_service,omitempty"`//  The service identifier
	DestinationService    string  `yaml:"receiver_service,omitempty"`//  The fully qualified name of the service that the server belongs to.my-svc.my-namespace

	SourceLabelsJson string  `yaml:"sender_labels,omitempty"`//  The sender service labels
	DestinationLabelsJson string  `yaml:"receiver_labels,omitempty"`//  The receiver service labels

	ContextType string `yaml:"request_type,omitempty"`  // type of context in relation to the ContextProtocol.
	// examples:
	// for ContextProtocol HTTP  ContextType=httpPath
	// for ContextProtocol=KAFKA  ContextType=kafkaTopic or consumerGroup

	RequestTimeSecondsFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeMinutesFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeHoursFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeMinutesParity int64 `yaml:"-"` // conversion of RequestTime timestamp // used in istio demo condition

	SourceNetIp net.IP `yaml:"-"`
	DestinationNetIp net.IP `yaml:"-"`

	SourceLabels map[string]string `yaml:"-"`
	DestinationLabels map[string]string `yaml:"-"`

}

// Messages structure contains a list of messages
type Messages struct {
	Messages []MessageAttributes `yaml:"messages,omitempty"`
}

// ToJson converts a structure into a json string
func (messageAttributes MessageAttributes) ToJson() string { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(messageAttributes, "", "  ")
	if err != nil {
		panic("error converting to json in isNumberOfFieldsEqual")
	}
	return (string(jsonBytes))
}

// ToJson converts a structure into a json string
func (messages Messages) ToJson() string { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(messages, "", "  ")
	if err != nil {
		panic("error converting to json in isNumberOfFieldsEqual")
	}
	return (string(jsonBytes))
}