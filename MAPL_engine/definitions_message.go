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

	//	SourceUid               string `yaml:"sender_uid,omitempty"`                //  Platform-specific unique identifier for the client instance of the source service. example: kubernetes: //redis-master-2353460263-1ecey.my-namespace
	SourceIp string `yaml:"sender_ip,omitempty"` //   Client IP address  example: 10.0.0.117
	//	SourceType              string `yaml:"sender_type,omitempty"`               //  Source workload instance type. example: redis-master-2353460263-1ecey is a "service" and "10.0.0.2" is "subnet"
	//	SourceName              string `yaml:"sender_name,omitempty"`               //  Source workload instance name. example: redis-master-2353460263-1ecey
	SourceNamespace string `yaml:"sender_namespace,omitempty"` //  Source workload instance namespace. example: my-namespace
	SourceCluster   string `yaml:"sender_cluster,omitempty"`   //  Source workload instance cluster. example: aws:edo
	//	SourcePrincipal         string `yaml:"sender_principal,omitempty"`          //  Authority under which the source workload instance is running. example: service-account-foo
	//	SourceOwner             string `yaml:"sender_owner,omitempty"`              //  Reference to the workload controlling the source workload instance.	example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-policy
	//	SourceWorkloadUid       string `yaml:"sender_workload_uid,omitempty"`       //  Unique identifier of the source workload.  example: istio://istio-system/workloads/istio-policy
	//	SourceWorkloadName      string `yaml:"sender_workload_name,omitempty"`      //  Source workload name. example: istio-policy
	//	SourceWorkloadNamespace string `yaml:"sender_workload_namespace,omitempty"` //  Source workload namespace.	example: istio-system

	// remark in kuberentes the SourceWorkloadName with the SourceWorkloadNamespace may uniquely identify the service
	// whereas the SourceName may identify a specific instance of the workload

	//	DestinationUid               string `yaml:"receiver_uid,omitempty"`                //  Platform-specific unique identifier for the server instance of the destination service. example: kubernetes://my-svc-234443-5sffe.my-namespace
	DestinationIp   string `yaml:"receiver_ip,omitempty"`   //  Server IP address. example: 10.0.0.104
	DestinationPort string `yaml:"receiver_port,omitempty"` //  The recipient port on the server IP address. example: 8080
	//	DestinationType              string `yaml:"receiver_type,omitempty"`               //  Destination workload instance type. example: redis-master-2353460263-1ecey is a "service" and "10.0.0.2" is "subnet"
	//	DestinationName              string `yaml:"receiver_name,omitempty"`               //  Destination workload instance name. example: istio-telemetry-2359333
	DestinationNamespace string `yaml:"receiver_namespace,omitempty"` //  Destination workload instance namespace. example: istio-system
	DestinationCluster   string `yaml:"receiver_cluster,omitempty"`   //  Destination workload instance cluster. example: aws:edo
	//	DestinationPrincipal         string `yaml:"receiver_principal,omitempty"`          //  Authority under which the destination workload instance is running. example: service-account
	//	DestinationOwner             string `yaml:"receiver_owner,omitempty"`              //  Reference to the workload controlling the destination workload instance. example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-telemetry
	//	DestinationWorkloadUid       string `yaml:"receiver_workload_uid,omitempty"`       //  Unique identifier of the destination workload. example: istio://istio-system/workloads/istio-telemetry
	//	DestinationWorkloadName      string `yaml:"receiver_workload_name,omitempty"`      //  Destination workload name. example: iistio-telemetry
	//	DestinationWorkloadNamespace string `yaml:"receiver_workload_namespace,omitempty"` //  Destination workload namespace. example: istio-system

	RequestPath   string `yaml:"request_path,omitempty"`   //  The HTTP URL path including query string
	RequestHost   string `yaml:"request_host,omitempty"`   //  HTTP/1.x host header or HTTP/2 authority header. Example: redis-master:3337
	RequestMethod string `yaml:"request_method,omitempty"` //  The HTTP method.
	//	RequestScheme    string `yaml:"request_uri,omitempty"`        //  URI Scheme of the request
	RequestSize int64 `yaml:"request_size,omitempty"` //  Size of the request in bytes.For HTTP requests this is equivalent to the Content-Length header.
	//	RequestTotalSize int64  `yaml:"request_total_size,omitempty"` //  Total size of HTTP request in bytes, including request headers, body and trailers.
	RequestTime      string `yaml:"request_time,omitempty"`       //  The timestamp when the destination receives the request.This should be equivalent to Firebase “now”. [https://firebase.google.com/docs/reference/android/com/google/firebase/Timestamp]
	RequestUseragent string `yaml:"request_user_agent,omitempty"` //  The HTTP User-Agent header.

	//	ResponseSize        int64         `yaml:"response_size,omitempty"`         //  Size of the response body in bytes
	//	ResponseTotalSize   int64         `yaml:"response_total_size,omitempty"`   //  Total size of HTTP response in bytes, including response headers and body.
	//	ResponseTime        string        `yaml:"response_time,omitempty"`         //  The timestamp when the destination produced the response.
	//	ResponseDuration    time.Duration `yaml:"response_duration,omitempty"`     //  duration    The amount of time the response took to generate.
	//	ResponseCode        int64         `yaml:"response_code,omitempty"`         //  The response’s HTTP status code.
	//	ResponseGrpcStatus  string        `yaml:"response_grpc_status,omitempty"`  //  The response’s gRPC status
	//	ResponseGrpcMessage string        `yaml:"response_grpc_message,omitempty"` //  The response’s gRPC status message.

	//	ConnectionMtls                string `yaml:"connection_mtls,omitempty"`                  //  Indicates whether a request is received over a mutual TLS enabled downstream connection.
	//	ConnectionRequestedServerName string `yaml:"connection_requested_server_name,omitempty"` // The requested server name (SNI) of the connection

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

	RequestJsonRaw         *[]byte `yaml:"json_raw,omitempty"`
	RequestJsonRawRelative *[]byte `yaml:"json_raw_relative,omitempty"`
	Domain                 string  `yaml:"domain,omitempty"`

	RequestTimeSecondsFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeMinutesFromMidnightUTC float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeHoursFromMidnightUTC   float64 `yaml:"-"` // conversion of RequestTime timestamp
	RequestTimeMinutesParity          int64   `yaml:"-"` // conversion of RequestTime timestamp // used in istio demo condition

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
