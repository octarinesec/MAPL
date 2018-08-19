# Istio MAPL Adapter 

## Overview

* MAPL (Manageable Access-control Policy Language) is a language for access control rules, designed for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.  
The language is described thoroughly in [MAPL Specification](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_SPEC.md).  
* The MAPL_adapter project provides a gRPC adapter for Istio's mixer for the management of access-control policy rules written in MAPL and using the MAPL Engine described in the [MAPL Engine](https://github.com/octarinesec/MAPL/tree/master/docs/MAPL_ENGINE.md) document.
* Istio's [bookinfo app](https://istio.io/docs/examples/bookinfo/) is used to demonstrate how the default behaviour of the app is easily controled using a tractable set of rules.   
 
 
## Demo

The adapter changes the behaviour of the bookinfo app by using rules in the [rules.yaml](insert link) file.
The default behaviour may be 
The policy rules block some of the services from communicating via HTTP.
 
  
The  rules are:
```yaml
rules:

  - rule_id: 0  # allow everything from istio-system. especially istio-ingressgateway
    sender: "istio-system.*" 
    receiver: "*"
    resource:
      resourceProtocol: "*"
      resourceType: "*"
      resourceName: "*"
    operation: "*"
    decision: allow

  - rule_id: 1  # block the details service. the review text will be un-available
    sender: "default.productpage-v1"
    receiver: "default.details-v1"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: block

  - rule_id: 2  # allow productpage-v1 to communicate with all the versions of the reviews service
    sender: "default.productpage-v1"
    receiver: "default.reviews-*"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow

  - rule_id: 3 # allow all the versions of the reviews service to communicate with the ratings-v1 service
    sender: "default.reviews-*"
    receiver: "default.ratings-v1"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: allow

  - rule_id: 4 # all except all reviews-v2 ... the black star reviews will be un-available
    sender: "default.reviews-v2"
    receiver: "default.ratings-v1"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/*"
    operation: GET
    decision: block

  - rule_id: 5  # allow the "login" path
    sender: "istio-system.istio-ingressgateway"
    receiver: "default.productpage-v1"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/login"
    operation: POST
    decision: alert

  - rule_id: 6  # but block the "logout" path. when signing out the main page will be un-avialble
    sender: "istio-system.istio-ingressgateway"
    receiver: "default.productpage-v1"
    resource:
      resourceProtocol: http
      resourceType: httpPath
      resourceName: "/logout"
    operation: GET
    decision: block

``` 

## Installation

Installing the adapter in a cluster with Kubernetes, Istio and the bookinfo app is described in [Adapter Installation](insert link) document. 