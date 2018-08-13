# MAPL

MAPL is a new language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.
MAPL makes it easier to declare and maintain access control rules. The language enables fine-grained control of traffic, with a resource based control model that takes into account the principals, action, resources on the principals, and conditions on traffic attributes, similar to AWS’s IAM policy model.

## Rule Syntax

Policy Rules have the following syntax:

`<sender, receiver, resource, operation> : <conditions> : <rule type>`

where, basically, a rule gives a decision of wheteher the sender (client) may do the operaion on the resource of the receiver (server) when the conditions apply.

### Sender and Receiver
Sender (client service) and Receiver (server service) names.
The names are case sensitive
The language allows wildcards (* and ?)

### Resources
A resource is defined as `<protocol>:<resource-type>:<resource-name>`
For example:
- `<HTTP>:<http_path>:<http_path_name>`
- `<KAFKA>:<kafka_topic>:<kafka_topic_name>`
- `<KAFKA>:<consumer_group>:<consumer_group_name>`
- `<TCP>:<port>:<port number>`

#### Protocols
The language currently ...

#### Resource Types
...

#### Resource names
The language allows wildcards

### Operation
A verb that defines an operation (method).
For example:
- for HTTP: GET, POST etc…
- for KAFKA: WRITE (Produce), READ (Consume).

The verb "read" corresponds to any of {GET ,HEAD, OPTIONS, TRACE}
The verb "write" corresponds to any of {POST, PUT, DELETE}

### Decision

The decision is ones of {allow, alert, block}

#### Defaults

The language was develpoed to handle whitelists.
Therefore, in case of several applicable rules, select to most restricting decision:
- By default, all messages are blocked.
- An explicit “allow” overrides this default.
- An explicit “alert” overrides any allows.
- An explicit “deny” overrides any allows and alerts.

Yet, it is very easy to use MAPL for blacklists.
Allow all traffic by adding the following rule:

```
  - rule_id: default_allow
    sender: "*"
    receiver: "*"
    resource:
      resourceProtocol: "*"
      resourceType: "*"
      resourceName: "*"
    operation: "*"
    decision: allow
```

# Examples

Allow service A.my_namespace to communicate with B.my_namespace over HTTP to any path using the GET method

```
  - rule_id: 0
    sender: "A.my_namespace"
    receiver: "B.my_namespace"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow
```

Allow all services of name *.my_namespace to communicate with B.my_namespace over HTTP to path /books using the GET method

```
  - rule_id: 1
    sender: "*.my_namespace"
    receiver: "B.my_namespace"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/books"
    operation: GET
    decision: allow
```

Allow service A.my_namespace to communicate with B.my_namespace over HTTP to all the paths of type /book/* using the GET method

```
  - rule_id: 2
    sender: "A.my_namespace"
    receiver: "B.my_namespace"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/books/*"
    operation: GET
    decision: allow
```

Allow service A.my_namespace to communicate with B.my_namespace over HTTP to all paths of type /book/* using any read method

```
  - rule_id: 3
    sender: "A.my_namespace"
    receiver: "B.my_namespace"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/books/*"
    operation: read
    decision: allow
```

Block service A.my_namespace from communicating with B.my_namespace over HTTP to path /books using any write method

```
  - rule_id: 4
    sender: "A.my_namespace"
    receiver: "B.my_namespace"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/books"
    operation: write
    decision: block
```