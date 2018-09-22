# Attributes Supported in the Conditions  

The following keywords are used in MAPL conditions with the value to-compare-with extracted from the message attributes.

<br>

| MAPL condition keyword | message attribute |
|:-------:|:-----:|
| payloadSize| message.RequestSize |
| requestUseragent | message.RequestUseragent |
| utcHoursFromMidnight | message.RequestTimeHoursFromMidnightUTC<br>(extracted from message.RequestTime)||
| senderLabel[key]* | message.SourceLabels[key] |
| receiverLabel[key]* | message.DestinationLabels[key] |  

\* see [Sender/Receiver Labels](#Sender/Receiver Labels)

## Sender/Receiver Labels

* Conditions on the labels have the following syntax:
   - <"senderLabel[key]", "EQ"/"EX"/"RE"/"NEQ"/"NEX"/"NRE", value>  
   where the condition compares the sender service label with the given key, using the method EQ (equality), EX (existence), RE (regular expression) or their negation, 
   to the value given in the condition. The value may contain wildcards (for the EQ/NEQ methods) or a regular expression (for the RE/NRE methods) 
    - <"receiverLabel[key]", "EQ"/"EX"/"RE"/"NEQ"/"NEX"/"NRE", value> is similar.
    - <"senderLabel[key]", "EQ"/"NEQ", "receiverLabel[key2]"> is used to compare a sender's label to a receiver's label. 
    - <"senderLabel[key]", "EQ"/"NEQ", "senderLabel[key2]">, <"receiverLabel[key]", "EQ"/"NEQ", "receiverLabel[key2]"> and <"receiverLabel[key]", "EQ"/"NEQ", "sebderLabel[key2]"> are not supported.

* Examples:  
see also  [rules_with_label_conditions.yaml](https://github.com/octarinesec/MAPL/tree/master/examples/rules_with_label_conditions.yaml)
          

```yaml
DNFconditions:
  - ANDconditions:
    - attribute: "senderLabel[key1]"
      method: EQ
      value: "abc"
    - attribute: "senderLabel[key2]"
      method: EQ
      value: "d*"
    - attribute: "receiverLabel[key1]"
      method: EQ
      value: "a?c"
    - attribute: "receiverLabel[key2]"
      method: RE
      value: "X.Z" [this is a regular expression]
  - ANDconditions:
    - attribute: "senderLabel[key2]"
      method: EQ
      value: "receiverLabel[key2]"
  - ANDconditions:
    - attribute: "senderLabel[key3]"
      method: EX
      value: "don't care"

```

* Sender (Source) and Receiver (Destination) labels are given in the message attributes (message.SourceLabels, message.DestinationLabels) 
* When read from a file (e.g. for testing) they are extracted from the sender_labels string fields (and similarly for the receiver_labels). For example:
```yaml
- message_id: 0
  sender_service: A.my_namespace
  sender_name: A-xxads-asdad
  sender_namespace: my_namespace
  sender_labels: "{key1:ABbC,key2:DEF,key3:XYZ}"
  receiver_service: B.my_namespace
  receiver_name: B-uasdx-asdgs
  receiver_namespace: my_namespace
  request_protocol: HTTP
  request_path: /book1
  request_method: GET
  request_size: 1023
  request_time: 2018-07-29T11:30:00-07:00
  request_user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36
```
  - sender_labels: "{key1:ABbC,key2:DEF,key3:XYZ}" is read into message.SourceLabelsJson field. Pay attention the no quotes are used and that keys and values are assumed to be strings.
  - message.SourceLabelsJson is then converted to the attribute message.SourceLabels (of type map[string]string), using the *addQuotesToJsonString* function:
    - message.SourceLabels["key1"]="ABbC"
    - message.SourceLabels["key2"]="DEF"
    - message.SourceLabels["key3"]="XYZ"
  - see for example:  [messages_test_with_labels_conditions.yaml](https://github.com/octarinesec/MAPL/tree/master/examples/messages_test_with_labels_conditions.yaml)
 
