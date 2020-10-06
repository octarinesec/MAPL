# Mongo Plugin
We created a mongo plugin to translate conditions from MAPL v2 into mongo query language. Querying the db directly speeds up the queries by about a factor of 5 to 10.

## Examples

1)  simple condition
```
 - rule_id: 0
   conditions:
      attribute: jsonpath:$.metadata.labels.foo
      method: EQ
      value: "bar"
```
Mongo query = ```{"raw.metadata.labels.foo":{"$eq":"bar"}}```

2) simple condition
```
 - rule_id: 0
   conditions:
      attribute: jsonpath:$.metadata.labels.foo
      method: NEX      
```
Mongo query = ```{"raw.metadata.labels.foo":{"$exists":false}}```

3)  condition with "Not Regex"
```
conditions:
  attribute: jsonpath:$.metadata.labels.foo
  method: NRE
  value: ar2
```
Mongo query = ```{"$and":[{"raw.metadata.labels.foo":{"$not":{"$regex":"ar2"}}},{"raw.metadata.labels.foo":{"$exists":true}}]}```

4) condition with "Not-And"
```
  conditions:
    NOT:
      AND:
      - attribute: "jsonpath:$.metadata.labels.foo"
        method: EQ
        value: bar

      - attribute: "jsonpath:$.spec.replicas"
        method: LT
        value: 4
```
Mongo query = ```{"$nor":[{"$and":[{"raw.metadata.labels.foo":{"$eq":"bar"}},{"raw.spec.replicas":{"$lt":4}}]}]}```

5) multilevel:
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

Mongo query = ```{"$nor":[{"raw.spec.containers":{"$elemMatch":{"$nor":[{"volumeMounts":{"$elemMatch":{"name":{"$eq":"xxx"}}}}]}}}]}```


6) key-value:
```
    conditions:
      ANY:
        parentJsonpathAttribute: "jsonpath:$.metadata.labels"
        condition:
          attribute: "jsonpath:$VALUE"
          method: EQ
          value: "ABC"
```

Mongo **Aggregate** query = 
```[ 
     {"$addFields":{"addedField.raw.metadata.labels":{"$objectToArray":"$raw.metadata.labels"}}},
     {"$match":{"addedField.raw.metadata.labels.v":{"$eq":"ABC"}}} 
   ]
```

## Mongo Plugin Limitations

1) Return values are not supported. The complete document is returned.

2) Comparison with strings that represent numbers with units. 

For example:


  conditions:
   ANY:
     parentJsonpathAttribute: "jsonpath:$.spec.containers[:]"
     condition:
       attribute: "jsonpath:$RELATIVE.resources.limits.cpu"
       method: GT
       value: 0.5 or 500m
       
If the document in the db contains the value 600m [0.6 core] then the query will fail as it tries to compare number (from MAPL) and string (in the db). A special pre-processing is needed before saving the document to the db.


3) Deepscan is not supported

4) Key/Value queries are supported only outside of arrays

