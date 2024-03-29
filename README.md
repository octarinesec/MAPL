# MAPL (Manageable Access-control Policy Language)

MAPL language was originally created for access control rules, especially for a microservices environment.
It is designed to be intuitive, rich and expressive, as well as simple and straightforward.

MAPL Language may be used in two contexts: 

1. General conditions on raw (json) data
2. Access control rules language

## Conditions

This is currently the main use-case.
Conditions syntax is described thoroughly in [MAPL Conditions V2](docs/MAPL_Conditions_v2.md).


## Access-Control


MAPL makes it easier to declare and maintain access control rules. The language enables fine-grained control of traffic, with a resource based control model that takes into account the principals, action, resources on the principals, and conditions on message and traffic attributes, similar to AWS’s IAM policy model.  
MAPL supports lists and wildcards in almost any field, thus allowing the policy maker to focus on creating policies without the need to have programming skills or regular expressions knowledge.


The MAPL rules have the following syntax:  

`<sender, receiver, protocol, resource, operation> : <conditions> : <decision>`

Essentially, a rule gives a decision whether the sender (client) may do the operation on the resource of the receiver (server) when the conditions apply.    
The language is described thoroughly in [MAPL v2 Syntax](docs/MAPL_SPEC_v2.md).   
Conditions syntax is described in [MAPL Conditions V2](docs/MAPL_Conditions_v2.md).    
See also previous syntax (MAPL v1) in [MAPL v1 Syntax](docs/MAPL_SPEC_v1.md).  

# MAPL Engine

Given a list of rules and message attributes, the MAPL engine gives a decision whether to allow, allow and alert or block the communication.  
The engine is documented in [MAPL Engine](docs/MAPL_ENGINE.md).  
The MAPL engine can be used in service meshes, API gateways and IAM solutions.  

# Mongo Plugin
We created a plugin to translate MAPL conditions into Mongo queries, as querying in the db speeds up the query by a factor of 5-10.  
See [Mongo Plugin](docs/Mongo_Plugin.md). 
