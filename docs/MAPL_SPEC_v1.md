# MAPL v1 Specification

MAPL (Manageable Access-control Policy Language) is a language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.  
MAPL makes it easier to declare and maintain access control rules. The language enables fine-grained control of traffic, with a resource based control model that takes into account the principals, action, resources on the principals, and conditions on message and traffic attributes, similar to AWS’s IAM policy model.  
MAPL supports lists and wildcards in almost any field, thus allowing the policy maker to focus on creating policies without the need to have programming skills or regular expressions knowledge.

## Rule Syntax

Policy rules have the following syntax:  

`<sender, receiver, protocol, resource, operation> : <conditions> : <decision>`

Essentially, a rule gives a decision whether the sender (client) may do the operation on the resource of the receiver (server) using the protocol when the conditions apply.

### Sender and Receiver
Sender services (clients) and Receiver services (servers) name structures defined as <senderName, senderType> or <receiverName, receiverType>.
Sender structure is comprised of sender name and sender type.  
Receiver structure is comprised of receiver name and receiver type.

- The language allows IPs and CIDRs. 
- The names are case sensitive strings, comprised of alphanumeric characters, '-', '/' and '.' and must not contain spaces or tabs.
- The language allows wildcards (* and ?).
- The language allows lists of names for multiple sender of receiver services, separated by ';'. Pay attention that all of the services in the list are of the same type as specified in the type.

Examples:
```
(1)
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
      
(2)
    sender: 
      senderName: "A.my_namespace;A.my_other_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
(3)
    sender: 
      senderName: "A;B;C.*"
      senderType: service
    receiver: 
      receiverName: "x;y.1?3;z"
      receiverType: service
```
### Protocol
Protocol: a string comprised of alphanumeric characters, '-', '/' and '.'  
for example: HTTP, KAFKA, TCP

### Resources
A resource is defined as `<resource-type, resource-name>`  

For example:  
- `<httpPath, http_path_name>`
- `<kafkaTopic, kafka_topic_name>`
- `<consumerGroup, consumer_group_name>`
- `<port, port number>`  
  
* Resource-Type: a string which is related to the protocol.  
 For example:  
    * for HTTP the resource type should always be "httpPath".
    * for KAFKA the resource type is one of "kafkaTopic" or "consumerGroup".
    * for TCP the resource type should always be "port".  
* Resource name: a case sensitive string, comprised of alphanumeric characters, '-', '/' and '.' and must not contain spaces or tabs. The language allows lists of resource names separated by ';'

### Operation
A verb that defines an operation (resource access method).  
For example:  
- for HTTP: GET, POST etc…  
- for KAFKA: PRODUCE, CONSUME  
- for TCP: always "*" (as TCP is a transport layer protocol) 
 
The language allows lists of resource names separated by ';'
The language allows for the following two words:  
The verb "read" corresponds to any of GET ,HEAD, OPTIONS, TRACE, CONSUME  
The verb "write" corresponds to any of POST, PUT, DELETE, PRODUCE  

### Conditions (MAPL v1) -  DEPRECATED

MAPL conditions part is a DNF (OR of ANDs) of one-attribute-conditions.  
This allows for rich and expressive enough testing of message attributes while keeping the rule simple and tractable.  
For example, one rule may have the following set of conditions:
```yaml
    DNFconditions:
      - ANDconditions:
        - attribute: payloadSize
          method: LE
          value: 4096
        - attribute: payloadSize
          method: GE
          value: 1024
      - ANDconditions:
        - attribute: payloadSize
          method: LE
          value: 20000
        - attribute: payloadSize
          method: GE
          value: 16384
      - ANDconditions:
        - attribute: utcHoursFromMidnight
          method: LE
          value: 16
        - attribute: utcHoursFromMidnight
          method: GE
          value: 14
```
which may be translated to:
```
(payloadSize>=1024 && payloadSize<=4096) || (payloadSize>=16384 && payloadSize<=20000) || (utcHoursFromMidnight>=14 && utcHoursFromMidnight<=16)
```
another rule may have the following set of conditions:
```yaml
    DNFconditions:
      - ANDconditions:
        - attribute: "senderLabel[key1]"
          method: EQ
          value: "abc"
       - ANDconditions:
        - attribute: "senderLabel[key2]"
          method: EQ
          value: "receiverLabel[key2]"
```      
which may be translated to: 
```
sender service has a label "abc" (for "key1") and the labels of the sender and receiver services for "key2" are equal.
```
for an extended spec for conditions on sender/receiver labels please see [Supported Attributes](https://github.com/octarinesec/MAPL/tree/master/docs/SUPPORTED_ATTRIBUTES.md) doc.

#### one-attribute-condition
A condition is defined as `<attribute, method, value>`  

* Attribute : a string from the [Supported Attributes](https://github.com/octarinesec/MAPL/tree/master/docs/SUPPORTED_ATTRIBUTES.md).
  
* Method:  
    - for string attributes: one of "EQ" (equal), "NE" (not equal), "RE" (regular expression match), "NRE" (regular expression mismatch).  
    - for int or float attributes: one of "EQ" (equal), "NE" (not equal), "LT" (lower than), "LE" (lower or equal than), "GT" (greater than), "GE" (greater or equal than).  
    - "EX", "NEX": existence or non-existence of an attribute regardless of value  
* Value: the value to test the extracted data against.  

Examples:  

payloadSize <= 4096:
```
<payloadSize, LE, 4096>
```
message daytime after 14:00:
```
<utcHoursFromMidnight, GT, 14>
```

### Decision

The decision is one of
- Default (rule not applicable - rule result is false)
- Allow
- Alert (allow and alert)
- Block

#### Defaults

The language was developed to handle whitelists.  
Therefore, in case of several applicable rules, it selects to most restricting decision:  
- By default, all messages are blocked.
- An explicit “allow” overrides this default.
- An explicit “alert” overrides any allows.
- An explicit “block” overrides any allows and alerts.  

Yet, it is very easy to use MAPL for blacklists, as follows.  
Allow all traffic by adding the following rule:

```
  - rule_id: default_allow
    sender: 
      senderName: "*"
      senderType: "*"
    receiver: 
      receiverName: "*"
      receiverType: "*"
    protocol: "*"
    resource:
      resourceType: "*"
      resourceName: "*"
    operation: "*"
    decision: allow
```

# Examples

### Sender and Receiver
Allow service A.my_namespace to communicate with service B.my_namespace over HTTP to any path using the GET method:

```
  - rule_id: 0
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow
```

Allow all services of name *.my_namespace to communicate with service B.my_namespace over HTTP to path /books using the GET method:

```
  - rule_id: 1
    sender: 
      senderName: "*.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/books"
    operation: GET
    decision: allow
```

### Resources and Operations
Allow service A.my_namespace to communicate with service B.my_namespace over HTTP to all the paths of type __/book/*__ using the **GET** method:

```
  - rule_id: 2
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource: 
      resourceType: httpPath
      resourceName: "/books/*"
    operation: GET
    decision: allow
```

Allow service A.my_namespace to communicate with service B.my_namespace over HTTP to all paths of type __/book/*__ using any **read** method:

```
  - rule_id: 3
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource: 
      resourceType: httpPath
      resourceName: "/books/*"
    operation: read
    decision: allow
```

Block service A.my_namespace from communicating with service B.my_namespace over HTTP to path __/books*__ using any **write** method:

```
  - rule_id: 4
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource: 
      resourceType: httpPath
      resourceName: "/books"
    operation: write
    decision: block
```

### Conditions (MAPL v1) - DEPRECATED

Block service A.my_namespace from communicating with B.my_namespace over HTTP to any path /books using GET method if
-  the payloadSize is between 1024 and 4096 bytes  
or  
-  the payloadSize is between 16384 and 20000 bytes  
or  
-  utcHoursFromMidnight is between 14 and 16 (i.e. the message was sent between 14:00 and 16:00)  

```
  - rule_id: 5
    sender: 
      senderName: "A.my_namespace"
      senderType: service
    receiver: 
      receiverName: "B.my_namespace"
      receiverType: service
    protocol: http
    resource: 
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    DNFconditions:
      - ANDconditions:
        - attribute: payloadSize
          method: LE
          value: 4096
        - attribute: payloadSize
          method: GE
          value: 1024
      - ANDconditions:
        - attribute: payloadSize
          method: LE
          value: 20000
        - attribute: payloadSize
          method: GE
          value: 16384
      - ANDconditions:
        - attribute: utcHoursFromMidnight
          method: LE
          value: 16
        - attribute: utcHoursFromMidnight
          method: GE
          value: 14
    decision: block

```

