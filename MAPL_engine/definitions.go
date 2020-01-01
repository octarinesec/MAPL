package MAPL_engine

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type GeneralStruct interface {
	// a general interface to structures.
	ToJson() string // This function is used when comparing structures read from yaml files to the resulting fields in the structure.
}

//-------------------rules-------------------------------------
type Sender struct {
	// if SenderName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	SenderName string                   `yaml:"senderName,omitempty" json:"senderName,omitempty" bson:"SenderName" structs:"SenderName,omitempty"`
	SenderType string                   `yaml:"senderType,omitempty" json:"senderType,omitempty" bson:"SenderType,omitempty" structs:"SenderType,omitempty"`
	SenderList []ExpandedSenderReceiver `yaml:"-" json:"senderList,omitempty" bson:"SenderList,omitempty" structs:"SenderList,omitempty"`
}

type Receiver struct {
	// if ReceiverName is a list (example: "srv1,srv2,srv123") then it is assumed that all are of the same type
	ReceiverName string                   `yaml:"receiverName,omitempty" json:"receiverName,omitempty" bson:"ReceiverName" structs:"ReceiverName,omitempty"`
	ReceiverType string                   `yaml:"receiverType,omitempty" json:"receiverType,omitempty" bson:"ReceiverType,omitempty" structs:"ReceiverType,omitempty"`
	ReceiverList []ExpandedSenderReceiver `yaml:"-" json:"receiverList,omitempty" bson:"ReceiverList,omitempty" structs:"ReceiverList,omitempty"`
}

// Resource structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Resource struct {
	/* Examples: // pay attention that the resource type should match the protocol
	path:<http_path_name>,
	kafkaTopic:<kafka_topic_name>
	consumerGroup:<consumer_group_name>
	port:<port number>
	*/
	ResourceType      string         `yaml:"resourceType,omitempty" json:"resourceType,omitempty" bson:"ResourceType,omitempty" structs:"ResourceType,omitempty"`
	ResourceName      string         `yaml:"resourceName,omitempty" json:"resourceName,omitempty" bson:"ResourceName,omitempty" structs:"ResourceName,omitempty"`
	ResourceNameRegex *regexp.Regexp `yaml:"-" json:"-,omitempty" bson:"ResourceNameRegex,omitempty" structs:"ResourceNameRegex,omitempty"`
}

// Condition structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Condition struct {
	Attribute        string         `yaml:"attribute,omitempty" json:"attribute" bson:"Attribute" structs:"Attribute,omitempty"`
	Method           string         `yaml:"method,omitempty" json:"method" bson:"Method" structs:"Method,omitempty"`
	Value            string         `yaml:"value,omitempty" json:"value" bson:"Value" structs:"Value,omitempty"`
	ValueInt         int64          `yaml:"-" json:"ValueInt,omitempty" bson:"ValueInt,omitempty" structs:"ValueInt,omitempty"`
	ValueFloat       float64        `yaml:"-" json:"ValueFloat,omitempty" bson:"ValueFloat,omitempty" structs:"ValueFloat,omitempty"`
	ValueRegex       *regexp.Regexp `yaml:"-" json:"ValueRegex,omitempty" bson:"ValueRegex,omitempty" structs:"ValueRegex,omitempty"`
	ValueStringRegex *regexp.Regexp `yaml:"-" json:"ValueStringRegex,omitempty" bson:"ValueStringRegex,omitempty" structs:"ValueStringRegex,omitempty"`

	AttributeIsSenderLabel    bool   `yaml:"-" json:"AttributeIsSenderLabel,omitempty" bson:"AttributeIsSenderLabel,omitempty" structs:"AttributeIsSenderLabel,omitempty"`
	AttributeSenderLabelKey   string `yaml:"-" json:"AttributeSenderLabelKey,omitempty" bson:"AttributeSenderLabelKey,omitempty" structs:"AttributeSenderLabelKey,omitempty"`
	AttributeIsReceiverLabel  bool   `yaml:"-" json:"AttributeIsReceiverLabel,omitempty" bson:"AttributeIsReceiverLabel,omitempty" structs:"AttributeIsReceiverLabel,omitempty"`
	AttributeReceiverLabelKey string `yaml:"-" json:"AttributeReceiverLabelKey,omitempty" bson:"AttributeReceiverLabelKey,omitempty" structs:"AttributeReceiverLabelKey,omitempty"`
	ValueIsReceiverLabel      bool   `yaml:"-" json:"ValueIsReceiverLabel,omitempty" bson:"ValueIsReceiverLabel,omitempty" structs:"ValueIsReceiverLabel,omitempty"`
	ValueReceiverLabelKey     string `yaml:"-" json:"ValueReceiverLabelKey,omitempty" bson:"ValueReceiverLabelKey,omitempty" structs:"ValueReceiverLabelKey,omitempty"`

	AttributeIsSenderObject      bool   `yaml:"-" json:"AttributeIsSenderObject,omitempty" bson:"AttributeIsSenderObject,omitempty" structs:"AttributeIsSenderObject,omitempty"`
	AttributeIsReceiverObject    bool   `yaml:"-" json:"AttributeIsReceiverObject,omitempty" bson:"AttributeIsReceiverObject,omitempty" structs:"AttributeIsReceiverObject,omitempty"`
	ValueIsReceiverObject      bool   `yaml:"-" json:"ValueIsReceiverObject,omitempty" bson:"ValueIsReceiverObject,omitempty" structs:"ValueIsReceiverObject,omitempty"`
	AttributeSenderObjectAttribute string `yaml:"-" json:"AttributeSenderObjectAttribute,omitempty" bson:"AttributeSenderObjectAttribute,omitempty" structs:"AttributeSenderObjectAttribute,omitempty"`
	AttributeReceiverObjectAttribute string `yaml:"-" json:"AttributeReceiverObjectAttribute,omitempty" bson:"AttributeReceiverObjectAttribute,omitempty" structs:"AttributeReceiverObjectAttribute,omitempty"`
	ValueReceiverObject string `yaml:"-" json:"ValueReceiverObject,omitempty" bson:"ValueReceiverObject,omitempty" structs:"ValueReceiverObject,omitempty"`

	AttributeIsJsonpath    bool   `yaml:"-" json:"AttributeIsJsonpath,omitempty" bson:"AttributeIsJsonpath,omitempty" structs:"AttributeIsJsonpath,omitempty"`
	AttributeJsonpathQuery string `yaml:"-" json:"AttributeJsonpathQuery,omitempty" bson:"AttributeJsonpathQuery,omitempty" structs:"AttributeJsonpathQuery,omitempty"`

	OriginalAttribute string `yaml:"-" json:"OriginalAttribute,omitempty" bson:"OriginalAttribute,omitempty" structs:"OriginalAttribute,omitempty"` // used in hash
	OriginalValue     string `yaml:"-" json:"OriginalValue,omitempty" bson:"OriginalValue,omitempty" structs:"OriginalValue,omitempty"`             // used in hash
}

// ANDConditions structure - part of the rule as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type ANDConditions struct {
	ANDConditions []Condition `yaml:"ANDconditions,omitempty" json:"ANDConditions,omitempty" bson:"ANDConditions,omitempty"`
}

// Rule structure - as defined in MAPL (https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md)
type Rule struct {
	// rule syntax:
	//	<sender, receiver, resource, operation> : <conditions> : <decision>
	//
	RuleID        string          `yaml:"rule_id,omitempty" json:"ruleID,omitempty" bson:"RuleID,omitempty" structs:"RuleID,omitempty"`
	Sender        Sender          `yaml:"sender,omitempty" json:"sender,omitempty" bson:"Sender" structs:"Sender,omitempty"`
	Receiver      Receiver        `yaml:"receiver,omitempty" json:"receiver,omitempty" bson:"Receiver" structs:"Receiver,omitempty"`
	Protocol      string          `yaml:"protocol,omitempty" json:"protocol,omitempty" bson:"ResourceProtocol" structs:"Protocol,omitempty"`
	Resource      Resource        `yaml:"resource,omitempty" json:"resource,omitempty" bson:"Resource" structs:"Resource,omitempty"`
	Operation     string          `yaml:"operation,omitempty" json:"operation,omitempty" bson:"Operation" structs:"Operation,omitempty"`
	DNFConditions []ANDConditions `yaml:"DNFconditions,omitempty" json:"dnfConditions,omitempty" bson:"DNFConditions,omitempty" structs:"DNFConditions,omitempty"`
	Decision      string          `yaml:"decision,omitempty" json:"decision,omitempty" bson:"Decision" structs:"Decision,omitempty"`


	Metadata      map[string]string          `yaml:"metadata,omitempty" json:"metadata,omitempty" bson:"Metadata" structs:"Metadata,omitempty"`

	Hash string `yaml:"hash,omitempty" json:"hash,omitempty" bson:"Hash" structs:"Hash,omitempty"`

	OperationRegex                    *regexp.Regexp `yaml:"o,omitempty" json:"o,omitempty" bson:"OperationRegex,omitempty" structs:"OperationRegex,omitempty"`
	AlreadyConvertedFieldsToRegexFlag bool           `yaml:"-,omitempty" json:"-,omitempty" bson:"-,omitempty" structs:"-,omitempty"` // default is false
}

// Rules structure contains a list of rules
type Rules struct {
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

//
type ExpandedSenderReceiver struct {
	Name   string         `yaml:"-" json:"Name,omitempty" bson:"Name,omitempty"`
	Type   string         `yaml:"-" json:"Type,omitempty" bson:"Type,omitempty"`
	Regexp *regexp.Regexp `yaml:"-" json:"Regexp,omitempty" bson:"Regexp,omitempty"`
	IsIP   bool           `yaml:"-" json:"IsIP,omitempty" bson:"IsIP,omitempty"`
	IsCIDR bool           `yaml:"-" json:"IsCIDR,omitempty" bson:"IsCIDR,omitempty"`
	CIDR   net.IPNet      `yaml:"-" json:"CIDR,omitempty"  bson:"CIDR,omitempty"`
	IP     net.IP         `yaml:"-" json:"IP,omitempty" bson:"IP,omitempty"`
}

//-------------------------------------------
type RuleAndExtras struct {
	MaplRule                       Rule   `json:"maplRule" binding:"required,dive" bson:"MaplRule" structs:"maplRule"`
	Account                        string `json:"account" bson:"account" structs:"account"`
	Enabled                        *bool  `json:"enabled" bson:"enabled" structs:"enabled"`
	Origin                         string `json:"origin" bson:"origin" structs:"origin"`
	BasedOnActivityCoveredByRuleId string `json:"basedOnActivityCoveredByRuleId" bson:"basedOnActivityCoveredByRuleId" structs:"basedOnActivityCoveredByRuleId"`
}

type RulesAndExtras struct {
	Rules []RuleAndExtras `json:"rules" binding:"required,dive" bson:"RulesAndExtras" structs:"rules"`
}

type RulesAndExtrasAndDeprecated struct {
	Rules        []RuleAndExtras `json:"rules" binding:"required,dive" bson:"RulesAndExtras" structs:"rules"`
	UpdatedRules []RuleAndExtras `json:"suggested_simple_rule_update" binding:"required,dive" bson:"UpdatedRules" structs:"suggested_simple_rule_update"`
	Deprecated   []string        `json:"deprecated_rules" binding:"required,dive" bson:"Deprecated" structs:"deprecated_rules"`
	NotUsed      []string        `json:"not_used_non_deprecatable_rules" binding:"required,dive" bson:"NotUsed" structs:"not_used_non_deprecatable_rules"`
	Used         []string        `json:"used_rules" binding:"required,dive" bson:"Used" structs:"used_rules"`
}

type MAPLDb struct {
	//bongo.DocumentBase `bson:",inline"`
	Id           string `json:"id" `
	Created      string `json:"created"`
	RuleAndExtras       `bson:",inline" bson:"RuleAndExtras"`
	MaplRuleHash string `json:"-" bson:"MaplRuleHash"`
}

//-------------------------------------------

// ToJson converts a structure into a json string
func (rule Rule) ToJson() string { // method of GeneralStruct interface
	jsonBytes, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		panic("error converting to json")
	}
	return (string(jsonBytes))
}

// ToJson converts a structure into a json string
func (rule Rule) ToJsonNoIndent() string { // method of GeneralStruct interface
	jsonBytes, err := json.Marshal(rule)
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

func (s *Sender) String() string {
	senderString := fmt.Sprintf("%v:%v", "{default type}:", s.SenderName)
	if s.SenderType != "" {
		senderString = fmt.Sprintf("%v:%v", s.SenderType, s.SenderName)
	}
	return senderString
}

func (r *Receiver) String() string {
	receiverString := fmt.Sprintf("%v:%v", "{default type}:", r.ReceiverName)
	if r.ReceiverType != "" {
		receiverString = fmt.Sprintf("%v:%v", r.ReceiverType, r.ReceiverName)
	}
	return receiverString
}

func (r *Resource) String() string {
	resourceString := "default:default"
	if r.ResourceType != "" {
		resourceString = fmt.Sprintf("%v:%v", r.ResourceType, r.ResourceName)
	}
	return resourceString
}

func (c *Condition) String() string {
	return fmt.Sprintf("(%v %v %v)", c.Attribute, c.Method, c.Value)
}

func (andConditions *ANDConditions) String() string {
	c_strings := []string{}
	for _, condition := range (andConditions.ANDConditions) {
		c_strings = append(c_strings, condition.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(c_strings, " && "))
}

type RuleStrings struct {
	RuleSetId        string
	SenderString     string
	ReceiverString   string
	ProtocolString   string
	ResourceString   string
	OperationString  string
	ConditionsString string
	DecisionString   string
}

func GetRuleStrings(r *Rule) RuleStrings {
	output := RuleStrings{}

	output.SenderString = r.Sender.String()
	output.ReceiverString = r.Receiver.String()

	output.ProtocolString = "default"
	if r.Protocol != "" {
		output.ProtocolString = r.Protocol
	}

	output.ResourceString = r.Resource.String()

	output.OperationString = "default"
	if r.Operation != "" {
		output.OperationString = r.Operation
	}

	output.DecisionString = "default"
	if r.Decision != "" {
		output.DecisionString = r.Decision
	}

	conditionsStrings := []string{}
	for _, andConditions := range (r.DNFConditions) {
		conditionsStrings = append(conditionsStrings, andConditions.String())
	}
	output.ConditionsString = strings.Join(conditionsStrings, " OR ")

	return output
}

//-------------------messages-------------------------------------

// MessageAttributes structure contains message attributes checked with the rules.
// The attributes were taken from Istio's HTTP message attributes [https://istio.io/docs/reference/config/policy-and-telemetry/attribute-vocabulary/]
type MessageAttributes struct {
	//--------------------------------------------------

	SourceUid               string `yaml:"sender_uid,omitempty"`                //  Platform-specific unique identifier for the client instance of the source service. example: kubernetes: //redis-master-2353460263-1ecey.my-namespace
	SourceIp                string `yaml:"sender_ip,omitempty"`                 //   Client IP address  example: 10.0.0.117
	SourceType              string `yaml:"sender_type,omitempty"`               //  Source workload instance type. example: redis-master-2353460263-1ecey is a "service" and "10.0.0.2" is "subnet"
	SourceName              string `yaml:"sender_name,omitempty"`               //  Source workload instance name. example: redis-master-2353460263-1ecey
	SourceNamespace         string `yaml:"sender_namespace,omitempty"`          //  Source workload instance namespace. example: my-namespace
	SourceCluster           string `yaml:"sender_cluster,omitempty"`            //  Source workload instance cluster. example: aws:edo
	SourcePrincipal         string `yaml:"sender_principal,omitempty"`          //  Authority under which the source workload instance is running. example: service-account-foo
	SourceOwner             string `yaml:"sender_owner,omitempty"`              //  Reference to the workload controlling the source workload instance.	example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-policy
	SourceWorkloadUid       string `yaml:"sender_workload_uid,omitempty"`       //  Unique identifier of the source workload.  example: istio://istio-system/workloads/istio-policy
	SourceWorkloadName      string `yaml:"sender_workload_name,omitempty"`      //  Source workload name. example: istio-policy
	SourceWorkloadNamespace string `yaml:"sender_workload_namespace,omitempty"` //  Source workload namespace.	example: istio-system

	// remark in kuberentes the SourceWorkloadName with the SourceWorkloadNamespace may uniquely identify the service
	// whereas the SourceName may identify a specific instance of the workload

	DestinationUid               string `yaml:"receiver_uid,omitempty"`                //  Platform-specific unique identifier for the server instance of the destination service. example: kubernetes://my-svc-234443-5sffe.my-namespace
	DestinationIp                string `yaml:"receiver_ip,omitempty"`                 //  Server IP address. example: 10.0.0.104
	DestinationPort              string `yaml:"receiver_port,omitempty"`               //  The recipient port on the server IP address. example: 8080
	DestinationType              string `yaml:"receiver_type,omitempty"`               //  Destination workload instance type. example: redis-master-2353460263-1ecey is a "service" and "10.0.0.2" is "subnet"
	DestinationName              string `yaml:"receiver_name,omitempty"`               //  Destination workload instance name. example: istio-telemetry-2359333
	DestinationNamespace         string `yaml:"receiver_namespace,omitempty"`          //  Destination workload instance namespace. example: istio-system
	DestinationCluster           string `yaml:"receiver_cluster,omitempty"`            //  Destination workload instance cluster. example: aws:edo
	DestinationPrincipal         string `yaml:"receiver_principal,omitempty"`          //  Authority under which the destination workload instance is running. example: service-account
	DestinationOwner             string `yaml:"receiver_owner,omitempty"`              //  Reference to the workload controlling the destination workload instance. example: kubernetes://apis/extensions/v1beta1/namespaces/istio-system/deployments/istio-telemetry
	DestinationWorkloadUid       string `yaml:"receiver_workload_uid,omitempty"`       //  Unique identifier of the destination workload. example: istio://istio-system/workloads/istio-telemetry
	DestinationWorkloadName      string `yaml:"receiver_workload_name,omitempty"`      //  Destination workload name. example: iistio-telemetry
	DestinationWorkloadNamespace string `yaml:"receiver_workload_namespace,omitempty"` //  Destination workload namespace. example: istio-system

	RequestPath      string `yaml:"request_path,omitempty"`       //  The HTTP URL path including query string
	RequestHost      string `yaml:"request_host,omitempty"`       //  HTTP/1.x host header or HTTP/2 authority header. Example: redis-master:3337
	RequestMethod    string `yaml:"request_method,omitempty"`     //  The HTTP method.
	RequestScheme    string `yaml:"request_uri,omitempty"`        //  URI Scheme of the request
	RequestSize      int64  `yaml:"request_size,omitempty"`       //  Size of the request in bytes.For HTTP requests this is equivalent to the Content-Length header.
	RequestTotalSize int64  `yaml:"request_total_size,omitempty"` //  Total size of HTTP request in bytes, including request headers, body and trailers.
	RequestTime      string `yaml:"request_time,omitempty"`       //  The timestamp when the destination receives the request.This should be equivalent to Firebase “now”. [https://firebase.google.com/docs/reference/android/com/google/firebase/Timestamp]
	RequestUseragent string `yaml:"request_user_agent,omitempty"` //  The HTTP User-Agent header.

	ResponseSize        int64         `yaml:"response_size,omitempty"`         //  Size of the response body in bytes
	ResponseTotalSize   int64         `yaml:"response_total_size,omitempty"`   //  Total size of HTTP response in bytes, including response headers and body.
	ResponseTime        string        `yaml:"response_time,omitempty"`         //  The timestamp when the destination produced the response.
	ResponseDuration    time.Duration `yaml:"response_duration,omitempty"`     //  duration    The amount of time the response took to generate.
	ResponseCode        int64         `yaml:"response_code,omitempty"`         //  The response’s HTTP status code.
	ResponseGrpcStatus  string        `yaml:"response_grpc_status,omitempty"`  //  The response’s gRPC status
	ResponseGrpcMessage string        `yaml:"response_grpc_message,omitempty"` //  The response’s gRPC status message.

	ConnectionMtls                string `yaml:"connection_mtls,omitempty"`                  //  Indicates whether a request is received over a mutual TLS enabled downstream connection.
	ConnectionRequestedServerName string `yaml:"connection_requested_server_name,omitempty"` // The requested server name (SNI) of the connection

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

	RequestJsonRaw *[]byte `yaml:"request_json_raw,omitempty"`
	Domain         string  `yaml:"domain,omitempty"`

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
