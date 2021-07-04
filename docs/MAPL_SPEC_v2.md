# MAPL v2 Syntax

MAPL (Manageable Access-control Policy Language) is a language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.  
MAPL makes it easier to declare and maintain access control rules. The language enables fine-grained control of traffic, with a resource based control model that takes into account the principals, action, resources on the principals, and conditions on message and traffic attributes, similar to AWS’s IAM policy model.  
MAPL supports lists and wildcards in almost any field, thus allowing the policy maker to focus on creating policies without the need to have programming skills or regular expressions knowledge.

## Changes from v1
Changes were made only to the “conditions” part of MAPL. The conditions may be tested separately from the rest of the rule (for example by Guardrails). The conditions part is a boolean tree (conditionsTree with as many levels as needed) where the end nodes are one-attribute-conditions. The one-attribute-conditions are tested against the message (or document) data.

## Rule Syntax

Policy rules have the following syntax:  

`<sender, receiver, protocol, resource, operation> : <conditions> : <decision>`

Essentially, a rule gives a decision whether the sender (client) may do the operation on the resource of the receiver (server) using the protocol when the conditions apply.

### Sender and Receiver
Sender services (clients) and Receiver services (servers) name structures.  
Sender is comprised of sender name and sender type.  
Receiver is comprised of receiver name and receiver type.

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

### Conditions (MAPL v2)

The conditions part is a boolean tree (conditionsTree with as many levels as needed) where the end nodes are one-attribute-conditions. The one-attribute-conditions are tested against the message (or document) data. See examples below.

see conditions syntax in [MAPL Conditions V2](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_Conditions_v2.md).


### Decision

The decision is ones of
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

### Predefined Strings and Lists

We introduce the ability to use strings and lists defined in a separate file in order to make the rules more readable. A reference to a list or a string starts with “#”. A list may contain references to strings. Lists takes precedence over strings (in case they have the same name).
 

Example:
```
predefinedStrings:
  dep: "Deployment"
  sts: "StatefulSet"

predefinedLists:
  workload:
    -  "Deployment"
    -  "#sts"
```
With the rule:
```
- rule_id: 0
    conditions:
      attribute: jsonpath:$.kind
      method: IN
      value: "#workload"
```


In GO:
```
err := yaml.Unmarshal([]byte(predefinedStringsAndListsYamlStr), &predefinedStringsAndLists)
predefinedStringsAndLists, err = validatePredefinedString(predefinedStringsAndLists)
err = yaml.Unmarshal([]byte(ruleYamlStr), &rule)
err = rule.SetPredefinedStringsAndLists(predefinedStringsAndLists)
```
setting default PredefinedStringsAndLists:
```
err:=SetGlobalPredefinedStringsAndLists(stringsAndlists)
```

# Examples

In Go:

check rule:
```
rule.Check(&message)
```
or (just conditions)
```
rule.TestConditions(&message)
```

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
