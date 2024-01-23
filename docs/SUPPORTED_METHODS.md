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
* IN, IS - value is in a list (comma seperated). Remark: the list is converted to a regex. 
* NIN - value is not in a list (comma seperated). Remark: the list is converted to a regex. 
