# Istio MAPL Adapter 

## Overview

* MAPL (Manageable Access-control Policy Language) is a language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.  
The language is described thoroughly in [MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).  
* The MAPL_adapter project provides a gRPC adapter for Istio's mixer for the management of access-control policy rules written in MAPL and using the MAPL Engine described in the [MAPL Engine](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_ENGINE.md) document.
* Istio's [bookinfo app](https://istio.io/docs/examples/bookinfo/) is used to demonstrate how the default behaviour of the app is easily controled using a tractable set of rules.   
 
 
## Demo

The adapter changes the behaviour of the bookinfo app by using rules in the [rules.yaml](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/rules/rules.yaml) file.  
For the default behaviour before the installation of the adapter, see [Istio Installation](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/docs/ISTIO_INSTALLATION.md) document.  
The policy rules change the app by blocking some of the services from communicating via HTTP. All communication is blocked by default. The rules state specifically which services are allowed to communicate with which services (a whitelist).  
Installation details are found in [Adapter Installation](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/docs/ADAPTER_INSTALLATION.md) document.
  
The  rules are:
```yaml
rules:

  - rule_id: 0  # allow everything from istio-system. especially istio-ingressgateway
    sender: 
        senderName: "*.istio-system"
        senderType: "service"
    receiver: 
        receiverName: "*"
        receiverType: "service"
    protocol: "*"
    resource:
      resourceType: "*"
      resourceName: "*"
    operation: "*"
    decision: allow

  - rule_id: 1  # block the details service. the review text will be un-available
    sender: 
        senderName: "productpage-v1.default"
        senderType: "service"
    receiver: 
        receiverName: "details-v1.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: block

  - rule_id: 2  # allow productpage-v1 to communicate with all the versions of the reviews service
    sender:  
        senderName: "productpage-v1.default"
        senderType: "service"
    receiver: 
        receiverName: "reviews-*.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow

  - rule_id: 3 # allow all the versions of the reviews service to communicate with the ratings-v1 service
    sender: 
        senderName: "reviews-*.default"
        senderType: "service"
    receiver: 
        receiverName: "ratings-v1.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow

  - rule_id: 4 # all except reviews-v2 ...
    sender: 
        senderName: "reviews-v2.default"
        senderType: "service"
    receiver: 
        receiverName: "ratings-v1.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: block

  - rule_id: 5  # allow the "login" path
    sender: 
        senderName: "*istio-ingressgateway*.istio-system"
        senderType: "service"
    receiver: 
        receiverName: "productpage-v1.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/login"
    operation: POST
    decision: alert

  - rule_id: 6  # but block the "logout" path
    sender: 
        senderName: "*istio-ingressgateway*.istio-system"
        senderType: "service"
    receiver: 
        receiverName: "productpage-v1.default"
        receiverType: "service"
    protocol: http
    resource:
      resourceType: httpPath
      resourceName: "/logout"
    operation: GET
    decision: block
``` 

## Installation

Installing the adapter in a cluster with Kubernetes, Istio and the bookinfo app is described in [Adapter Installation](https://github.com/octarinesec/MAPL/tree/master/MAPL_adapter/docs/ADAPTER_INSTALLATION.md) document.

## Demo Versions

<br>

|MAPL version| istio release | git tag | docker image tag |
|:-------:|:-------:|:-----:|:-----:|
1|1.0.0|0.1|octarinesec/mapl_adapter:0.1
2|1.0.0|0.2|octarinesec/mapl_adapter:0.2

The MAPL versions are described in  [MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).  

## Adapter Roadmap

* fix broken logs
* check use of istio's workload name and namespace
* find better way to update rules. also, how to allow many rule files?
* test the CACHE_TIMEOUT_SECS effect
 

 