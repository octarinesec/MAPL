# MAPL (Manageable Access-control Policy Language)
MAPL is a language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.  
MAPL makes it easier to declare and maintain access control rules. The language enables fine-grained control of traffic, with a resource based control model that takes into account the principals, action, resources on the principals, and conditions on message and traffic attributes, similar to AWS’s IAM policy model.

The MAPL rules have the following syntax:  

`<sender, receiver, protocol, resource, operation> : <conditions> : <decision>`

Essentially, a rule gives a decision wheteher the sender (client) may do the operaion on the resource of the receiver (server) using the protocol when the conditions apply.  
The language is described thoroughly in [MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).

# MAPL Engine

Given a list of rules and message attributes, the MAPL engine gives a decision whether to allow, allow and alert or block the communication.  
The engine is documented in [MAPL Engine](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_ENGINE.md).  
The MAPL engine can be used in service meshes, API gateways and IAM solutions.  

# Demo
A demonstration of the use of the MAPL engine for service-to-service authorization in [Istio](https://istio.io/) using a gRPC adapter for [Istio’s mixer service](https://istio.io/docs/concepts/policies-and-telemetry/) can be found in [MAPL_adapter](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/).

## Demo Versions

<br>

|MAPL version| istio release | git tag | docker image tag |
|:-------:|:-------:|:-----:|:-----:|
1|1.0.0|0.1|octarinesec/mapl_adapter:0.1
2|1.0.0|0.2|octarinesec/mapl_adapter:0.2

The MAPL versions are described in  [MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).  

# Status of the MAPL Project
This project is still under active development.  
If you have any questions about MAPL, or about how to use the MAPL engine, please contact MAPL@octarinesec.com  

# Engine Roadmap
- Currently the engine supports service to service communication. We need to support ingress and egress by IP or CIDR  
- Support Istio's source.labels and destination.labels  
- Suppert HTTP request headers
- Add patterns to the wildcard use (*,?) similar to fnmatch [https://www.gnu.org/software/libc/manual/html_node/Wildcard-Matching.html]? Or allow input of regex in rules?
- Add more message attributes support in the conditions
- Allow for definitions of service groups for reducing the number of rules (for example, use source.labels and destination.labels in the conditions?)


# TO-DO:

- handle EX
- add auto-test with full message to see if they follow the syntax
- fix convertConditionStringToIntFloatRegex. need to avoid putting default values for values that are actually used later

