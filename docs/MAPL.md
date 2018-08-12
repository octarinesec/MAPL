# MAPL

## Rule Syntax

Policy Rules have the following syntax:

<sender, receiver, resource, operation> : <conditions> : <rule type>

### Sender and Receiver
Sender (client service) and Receiver (server service) names.
The names are case sensitive
The language allows wildcards (* and ?)

### Resources
A resource is defined as <protocol>:<resource-type>:<resource-name>
For example:
- <HTTP>:<http_path>:<http_path_name>,
- <kafka>:<kafka_topic>:<kafka_topic_name>
- <kafka>:<consumer_group>:<consumer_group_name>
- <TCP>:<port>:<port number>

#### Protocols
The language currently ...

#### Resource Types
...

#### Resource names
The language allows wildcards

### Operation
A verb that defines an operation (method).
For example:
- for http: GET, POST etc…
- for kafka: WRITE (Produce), READ (Consume).

The verb "read" corresponds to any of {GET ,HEAD, OPTIONS, TRACE}
The verb "write" corresponds to any of {POST, PUT, DELETE}

### Decision

The decision is ones of {allow, alert, block}

#### Defaults

The language was develpoed to handle whitelists.
Therefore, in case of several applicable rules, select to most restricting decision:
- By default, all messages are denied (blocked).
- An explicit “allow” overrides this default.
- An explicit “alert” overrides any allows.
- An explicit “deny” overrides any allows and alerts.

Yet, it is very easy to use MAPL for blacklists:
Just add the following rule:

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