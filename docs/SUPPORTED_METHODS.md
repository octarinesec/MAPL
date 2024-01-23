# Methods Supported in the Conditions

For numerical attributes (int or float):
* GE - greater/equal
* GT - greater than
* LE - lower/equal
* LT - lower than
* EQ - equal

For string attributes:
* EQ - string equality
* NE, NEQ - not equal
* RE - regular expression equality
* NRE - regular expressions inequality
* EX - field exists (used with jsonpath) regardless of value
* NEX - field does not exist (used with jsonpath) regardless of value
* IN, IS - value is in a list (comma seperated) of exact values. Remark: the list is converted to a regex. 
* NIN - value is not in a list (comma seperated) of exact values. Remark: the list is converted to a regex. 
* CONTAINS - attribute value string contains one of the words in a list of words (often used with variables)
* NCONTAINS - attribute value string does not contain one of the words in a list of words
* INSTR - attribute string is a substring of the condition value (used with variables)


Examples:

* Test if the kind field in the json is one of the exact values in the list.

      attribute: jsonpath:$.kind
      method: IN
      value: "[Pod,Deployment]"
remark: The value "Pod" will result in "true" whereas "Pods" will result in "false".

* Test if the args field in the json contains one of the words.

      attribute: "jsonpath:$.args"
      method: CONTAINS
      value: "build,tests"
remark: The value "build project.go" will result in "true".  The value "run tests" will result in "true" whereas "run test" will result in "false".

* Test if the args field in the json contains one of the variables in the argsVariable variable.

      attribute: "jsonpath:$.args"
      method: CONTAINS
      value: "#argsVariable"

* Test if the filename field in the json appears as a substring of renamingArgs variable.

      attribute: jsonpath:$.filename
      method: INSTR
      value: "#renamingArgs"