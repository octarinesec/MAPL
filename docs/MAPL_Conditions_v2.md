# MAPL v2 Conditions

MAPL conditions are arranged as boolean tree (conditionsTree with as many levels as needed) where the end nodes are one-attribute-conditions. The one-attribute-conditions are tested against the message (or document) data. See examples below.


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


# Examples

In Go:
```
rule.TestConditions(&message)
```

1) One condition:
```
conditions:
  attribute: jsonpath:$.abc
  method: EQ
  value: "ABC"
```
The following is essentially the same: [the **condition** keyword]
```
conditions:
  condition:    
    attribute: jsonpath:$.abc
    method: EQ
    value: "ABC"
```
The following is essentially the same: [the **conditionsTree** keyword]
```
conditions:
  conditionsTree:    
    attribute: jsonpath:$.abc
    method: EQ
    value: "ABC"
```

2) AND Node: [AND between sub-nodes. AND between two conditions in this example]
```
conditions:
  AND:
  - attribute: jsonpath:$.kind
    method: EQ
    value: "Deployment"
  - attribute: jsonpath:$.abc
    method: EQ
    value: "ABC"
```
3) OR Node:  [OR between sub-nodes. OR between two conditions in this example]
```
conditions:
  OR:
  - attribute: jsonpath:$.kind
    method: EQ
    value: "Deployment"
  - attribute: jsonpath:$.abc
    method: EQ
    value: "ABC"
```
4) Not Node:  [NOT of one sub-node. NOT of one condition in this example]
```
conditions:
  NOT:
    attribute: jsonpath:$.abc
    method: EQ
    value: "ABC"
```
5) Multi-level conditions:

example I:
```
conditions:
  AND:
  - attribute: jsonpath:$.kind
    method: EQ
    value: "Deployment"
  - OR:
    - attribute: jsonpath:$.abc
      method: EQ
      value: "ABC"
    - attribute: jsonpath:$.xyz
      method: EQ
      value: "XYZ"
```
example II:
```
conditions:
  OR:
  - NOT: 
      attribute: jsonpath:$.kind
      method: EQ
      value: "Deployment"
  - AND:
    - attribute: jsonpath:$.abc
      method: EQ
      value: "ABC"
    - attribute: jsonpath:$.xyz
      method: EQ
      value: "XYZ"
```

etc...

There is no limit on the amount of levels

6) Array Handling

There are two types of nodes:
ALL: all the elements of the array must be satisfied. 
ANY: at least one element satisfies the conditions.

The **$RELATIVE** keyword means that the jsonpath refers to the sub-document given by the parentJsonpathAttribute attribute. For example: jsonpath:$.spec.containers[:] will create an array of container sub-documents. 

6a) ALL:
The following condition Tree will return true if there is at least one container without resource limits on the cpu or memory.
```
conditions:
  NOT:
    ALL:
      parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
      condition:
        AND:
        - attribute: "jsonpath:$RELATIVE.resources.limits.cpu"
          method: EX
        - attribute: "jsonpath:$RELATIVE.resources.limits.memory"
          method: EX
```
6b) ANY:
This example is equivalent to the previous one
```
conditions:
  ANY:
    parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
    OR:
    - attribute: "jsonpath:$RELATIVE.resources.limits.cpu"
      method: NEX    
    - attribute: "jsonpath:$RELATIVE.resources.limits.memory"
      method: NEX
```

6c) Multi-level arrays:
```
conditions:
  ALL:
    parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
    ANY:
      parentJsonpathAttribute: "jsonpath:$RELATIVE.volumeMounts[:]"
      condition:
        attribute: "jsonpath:$RELATIVE.name"
        method: EQ
        value: "xxx"
```
6d) key-value:

The **$KEY** and **$VALUE** keywords may be used on sub-documents as follows:

Check if a label with key “abc” exists:
```
conditions:
  ANY:
    parentJsonpathAttribute: "jsonpath:$.metadata.labels"
    condition:
      attribute: "jsonpath:$KEY"
      method: EQ
      value: "abc"
```
Check if a label with value “abc” exists:
```
conditions:
  ANY:
    parentJsonpathAttribute: "jsonpath:$.metadata.labels"
    condition:
      attribute: "jsonpath:$VALUE"
      method: EQ
      value: "abc"
```

multi-level:
```
conditions:
  ANY:
    parentJsonpathAttribute: "jsonpath:$.spec.containers"
    ANY:
      parentJsonpathAttribute: "jsonpath:$RELATIVE.metadata.labels"
      condition:
        attribute: "jsonpath:$VALUE"
        method: EQ
        value: "DEF"
```

6e) return values:

Nodes of type ANY may return values collected from their array sub-documents.
The returnValueJsonpath field is a map[string]string of jsonpath attributes that are returned for every sub-document which satisfies the node conditions.
In the following rule the name, resources sub-document and the complete sub-document are all returned as interfaces.
```
conditions:
  ANY:
    parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
    returnValueJsonpath:
      name: "jsonpath:$RELATIVE.name"
      resources: "jsonpath:$RELATIVE.resources"
      all: "jsonpath:$RELATIVE*"
    AND:
     - attribute: "jsonpath:$RELATIVE.resources.limits.cpu"
       method: EX
     - attribute: "jsonpath:$RELATIVE.resources.limits.memory"
       method: EX
```

Return values flow up the nodes to the parent node from the ANY nodes. For example this rule will get the return value “name” from the ANY node both the ANY node and the condition on the resource kind are satisfied.

```
conditions:
  AND:
  - Attribute: jsonpath:$.kind
    Method: EQ
    Value: "Deployment"
  - ANY:
      parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
      returnValueJsonpath:
        name: "jsonpath:$RELATIVE.name"
     AND:
     - attribute: "jsonpath:$RELATIVE.resources.limits.cpu"
       method: EX
     - attribute: "jsonpath:$RELATIVE.resources.limits.memory"
       method: EX
```

More than one “ANY” nodes under one parent nodes are handled as follows:

NOT - returns empty data
AND - returns the last one
OR - returns the first one

ANY node under another ANY node: returns data only from the top level.

7) deepscan:

MAPL v2 supports a kind of wildcard in the key of the jsonpath

Example:

```jsonpath:$..spec.containers```	(note the double dots) will return results (in an array format) both for 
```jsonpath:$.spec.containers``` and ```jsonpath:$.spec.template.spec.containers```



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
- conditions:
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
