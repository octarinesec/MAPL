package MAPL_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/toolkits/slice"
	"github.com/yalp/jsonpath"
	"go.mongodb.org/mongo-driver/bson"
	dc "gopkg.in/getlantern/deepcopy.v1"
	"sort"
	"strings"
)

//-----------------------
// ConditionsTree
//-----------------------
type ConditionsTree struct {
	ConditionsTree Node `yaml:"conditionsTree,omitempty" json:"conditionsTree,omitempty" bson:"conditionsTree,omitempty" structs:"conditionsTree,omitempty"`
}

func (c *ConditionsTree) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var aux interface{}
	if err := unmarshal(&aux); err != nil {
		return err
	}
	var n Node
	n, err := ParseConditionsTree(aux)
	if err != nil {
		return err
	}

	c.ConditionsTree = n
	return nil

}

func (c *ConditionsTree) UnmarshalJSON(data []byte) error {

	if len(data) == 2 {
		if data[0] == '{' && data[1] == '}' {
			c.ConditionsTree = nil
			return nil
		}
		if data[0] == '[' && data[1] == ']' {
			c.ConditionsTree = nil
			return nil
		}
	}

	var aux interface{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var n Node
	n, err := ParseConditionsTree(aux)
	if err != nil {
		return err
	}

	c.ConditionsTree = n
	return nil

}

// UnmarshalBSON implements driverBson.Unmarshal.
// we actually use the json unmarshaller
func (c *ConditionsTree) UnmarshalBSON(data []byte) error {
	var doc map[string]interface{}
	if err := bson.Unmarshal(data, &doc); err != nil {
		return err
	}

	docRaw, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	return json.Unmarshal(docRaw, c)
}

func (c ConditionsTree) MarshalBSON() ([]byte, error) {
	jsonRaw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(jsonRaw, &doc); err != nil {
		return nil, err
	}

	return bson.Marshal(doc)
}

//--------------------------------------
// Node Interface
//--------------------------------------
type Node interface {
	Eval(message *MessageAttributes) (bool, []map[string]interface{})
	Append(node Node)
	PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error
	String() string // to-do: order terms so that hash will be the same
	ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error)
}

type AnyAllNode interface {
	Node
	SetParentJsonpathAttribute(parentJsonpathAttribute string)
	GetParentJsonpathAttribute() string
	GetParentJsonpathAttributeArray() []string
	SetReturnValueJsonpath(returnValueJsonpath map[string]string)
	GetReturnValueJsonpath() map[string]string
	GetPreparedJsonpathQuery() []jsonpath.FilterFunc
}

//--------------------------------------
// And Node
//--------------------------------------
type And struct {
	Nodes []Node `yaml:"AND,omitempty" json:"AND,omitempty" bson:"AND,omitempty" structs:"AND,omitempty"`
}

func (a *And) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	extraData := []map[string]interface{}{}
	for _, node := range a.Nodes {
		flag, extraDataTemp := node.Eval(message)
		if len(extraDataTemp) > 0 {
			extraData = extraDataTemp
		}
		if flag == false {
			return false, extraData // no need to check the rest
		}
	}
	return true, extraData
}
func (a *And) Append(node Node) {
	a.Nodes = append(a.Nodes, node)
}

func (a *And) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	for _, node := range a.Nodes {
		err := node.PrepareAndValidate(stringsAndlists)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *And) String() string {
	return AndOrString(a.Nodes, " && ")
}

func AndOrString(a_nodes []Node, andOrStr string) string {

	if len(a_nodes) == 1 {
		return a_nodes[0].String()
	}

	arr := []string{}
	for _, node := range a_nodes {
		arr = append(arr, node.String())
	}
	sort.Strings(arr)
	str := "("
	for i_a, a := range arr {
		if i_a < len(arr)-1 {
			str += a + andOrStr
		} else {
			str += a
		}
	}
	str += ")"
	return str
}

//--------------------------------------
// Or Node
//--------------------------------------
type Or struct {
	Nodes []Node `yaml:"OR,omitempty" json:"OR,omitempty" bson:"OR,omitempty" structs:"OR,omitempty"`
}

func (o *Or) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	flagOut := false
	extraDataOut := []map[string]interface{}{}
	for _, node := range o.Nodes {
		flag, extraData := node.Eval(message)
		// if flag {
		//	return true, extraData // no need to check the rest
		//}
		flagOut = flagOut || flag
		if flag {
			for _, e := range extraData {
				extraDataOut = append(extraDataOut, e)
			}
		}
	}
	return flagOut, extraDataOut
}
func (o *Or) Append(node Node) {
	o.Nodes = append(o.Nodes, node)
}
func (o *Or) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	for _, node := range o.Nodes {
		err := node.PrepareAndValidate(stringsAndlists)
		if err != nil {
			return err
		}
	}
	return nil
}
func (o *Or) String() string {
	return AndOrString(o.Nodes, " || ")
}

//--------------------------------------
// Not Node
//--------------------------------------
type Not struct {
	Node Node `yaml:"NOT,omitempty" json:"NOT,omitempty" bson:"NOT,omitempty" structs:"NOT,omitempty"`
}

func (n *Not) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	flag, _ := n.Node.Eval(message)
	return !flag, []map[string]interface{}{}
}
func (n *Not) Append(node Node) {
	n.Node = node
}
func (n *Not) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {

	err := n.Node.PrepareAndValidate(stringsAndlists)
	return err

}
func (n *Not) String() string {
	str := fmt.Sprintf("!(%v)", n.Node.String())
	return str
}

//--------------------------------------
// Any Node
//--------------------------------------
type Any struct {
	ParentJsonpathAttribute                      string
	ParentJsonpathAttributeArray                 []string
	ParentJsonpathAttributeOriginal              string
	ReturnValueJsonpath                          map[string]string
	ReturnValuePreparedJsonpathQuery             map[string]jsonpath.FilterFunc
	ReturnValuePreparedJsonpathQueryRelativeFlag map[string]bool
	ReturnValueJsonpathOriginal                  map[string]string
	Node                                         Node                  `yaml:"condition,omitempty" json:"condition,omitempty" bson:"condition,omitempty" structs:"condition,omitempty"`
	PreparedJsonpathQuery                        []jsonpath.FilterFunc `yaml:"-,omitempty" json:"-,omitempty"`
}

func (a *Any) MarshalJSON() ([]byte, error) {

	parentJsonpathAttributeString := a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal) > 0 {
		parentJsonpathAttributeString = a.ParentJsonpathAttributeOriginal
	}

	returnValueJsonpath := a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal) > 0 {
		returnValueJsonpath = a.ReturnValueJsonpathOriginal
	}

	str := fmt.Sprintf(`{"ANY":{"parentJsonpathAttribute":"%v",`, parentJsonpathAttributeString)
	if len(returnValueJsonpath) > 0 {
		returnValueJsonpathJson, _ := json.Marshal(returnValueJsonpath)
		str = fmt.Sprintf(`%v"returnValueJsonpath": %v,`, str, string(returnValueJsonpathJson))
	}

	conditionBytes, err := json.Marshal(a.Node)
	if err != nil {
		return []byte{}, err
	}
	str = fmt.Sprintf(`%v"condition":%v}}`, str, string(conditionBytes))

	return []byte(str), nil
}

func (a *Any) Eval(message *MessageAttributes) (bool, []map[string]interface{}) { // to-do: return errors
	if message.RequestRawInterface != nil && a.PreparedJsonpathQuery != nil {
		return evalAnyRawInterface(a, message)
	} else {
		return evalAnyRawBytes(a, message)
	}
}

func evalAnyRawInterface(a *Any, message *MessageAttributes) (bool, []map[string]interface{}) {

	rawArrayData, err := getArrayOfInterfaces(a, message)
	if err != nil {
		return false, []map[string]interface{}{}
	}

	extraData := []map[string]interface{}{}
	result := false
	checkAllValuesInTheArray := false
	if len(a.ReturnValueJsonpath) > 0 {
		checkAllValuesInTheArray = true
	}
	originalRequestRawInterfaceRelative := message.RequestRawInterfaceRelative
	for _, val := range rawArrayData {
		message.RequestRawInterfaceRelative = &val
		flag, _ := a.Node.Eval(message)
		if flag {
			result = true
			if a.ReturnValueJsonpath != nil {

				extraDataTemp := getExtraDataFromInterface(a.ReturnValuePreparedJsonpathQuery, a.ReturnValuePreparedJsonpathQueryRelativeFlag, a.ReturnValueJsonpath, message)
				extraData = append(extraData, extraDataTemp)

			}
			if !checkAllValuesInTheArray {
				message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
				return result, extraData
			}
		}
	}

	message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
	return result, extraData
}
func evalAnyRawBytes(a *Any, message *MessageAttributes) (bool, []map[string]interface{}) {

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false, []map[string]interface{}{}
	}

	extraData := []map[string]interface{}{}
	result := false
	checkAllValuesInTheArray := false
	if len(a.ReturnValueJsonpath) > 0 {
		checkAllValuesInTheArray = true
	}
	originalRequestJsonRawRelative := message.RequestJsonRawRelative
	for _, val := range rawArrayData {
		message.RequestJsonRawRelative = &val
		flag, _ := a.Node.Eval(message)
		if flag {
			result = true
			if a.ReturnValueJsonpath != nil {
				extraDataTemp := getExtraDataFromByteArray(a.ReturnValueJsonpath, a.ReturnValuePreparedJsonpathQueryRelativeFlag, message)
				extraData = append(extraData, extraDataTemp)
			}
			if !checkAllValuesInTheArray {
				message.RequestJsonRawRelative = originalRequestJsonRawRelative
				return result, extraData
			}
		}
	}

	message.RequestJsonRawRelative = originalRequestJsonRawRelative
	return result, extraData
}
func (a *Any) Append(node Node) {
	a.Node = node
}
func (a *Any) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {

	err := a.Node.PrepareAndValidate(stringsAndlists)
	if err != nil {
		return err
	}

	a.ParentJsonpathAttributeArray = strings.Split(a.GetParentJsonpathAttribute(), ",")

	for _, j := range a.GetParentJsonpathAttributeArray() {
		preparedJsonpath, err := prepareJsonpathQuery(j)
		if err != nil {
			return err
		}
		a.PreparedJsonpathQuery = append(a.PreparedJsonpathQuery, preparedJsonpath)
	}
	return nil
}

func prepareJsonpathQuery(query string) (jsonpath.FilterFunc, error) {
	query = strings.Replace(query, "$RELATIVE", "$", -1)
	if query == "$*" {
		query = "$.*"
	}
	if strings.Contains(query, "$KEY") || strings.Contains(query, "$VALUE") {
		preparedJsonpath, _ := jsonpath.Prepare("$.*") // just instead of nil. we are not going to use it
		return preparedJsonpath, nil
	} else {
		preparedJsonpath, err := jsonpath.Prepare(query)
		if err != nil {
			return nil, err
		}
		return preparedJsonpath, err
	}
}

func (a *Any) String() string {
	str1 := a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal) > 0 {
		str1 = a.ParentJsonpathAttributeOriginal
	}
	str2 := a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal) > 0 {
		str2 = a.ReturnValueJsonpathOriginal
	}
	str := fmt.Sprintf("[ANY<%v;%v>:%v]", str1, str2, a.Node.String())
	return str
}

func (a *Any) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.ParentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.ParentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *Any) GetParentJsonpathAttribute() string {
	return a.ParentJsonpathAttribute
}

func (a *Any) GetParentJsonpathAttributeArray() []string {
	return a.ParentJsonpathAttributeArray
}

func (a *Any) SetReturnValueJsonpath(returnValueJsonpath map[string]string) {
	dc.Copy(&a.ReturnValueJsonpathOriginal, &returnValueJsonpath)
	dc.Copy(&a.ReturnValueJsonpath, &returnValueJsonpath)
	a.ReturnValuePreparedJsonpathQuery = make(map[string]jsonpath.FilterFunc)
	a.ReturnValuePreparedJsonpathQueryRelativeFlag = make(map[string]bool)
	for queryName, queryString := range returnValueJsonpath {
		a.ReturnValuePreparedJsonpathQueryRelativeFlag[queryName] = false
		if strings.HasPrefix(queryString, "jsonpath:$RELATIVE") {
			a.ReturnValuePreparedJsonpathQueryRelativeFlag[queryName] = true
		}
		a.ReturnValueJsonpath[queryName] = strings.Replace(queryString, "jsonpath:$RELATIVE", "$", 1)
		preparedQuery, err := prepareJsonpathQuery(a.ReturnValueJsonpath[queryName])
		if err == nil {
			a.ReturnValuePreparedJsonpathQuery[queryName] = preparedQuery
		} else {
			a.ReturnValuePreparedJsonpathQuery[queryName] = nil
		}
	}
}

func (a *Any) GetReturnValueJsonpath() map[string]string {
	return a.ReturnValueJsonpathOriginal
}

func (a *Any) GetPreparedJsonpathQuery() []jsonpath.FilterFunc {
	return a.PreparedJsonpathQuery
}

//--------------------------------------
// All Node
//--------------------------------------
type All struct {
	ParentJsonpathAttribute                      string
	ParentJsonpathAttributeArray                 []string
	ParentJsonpathAttributeOriginal              string
	ReturnValueJsonpath                          map[string]string
	ReturnValueJsonpathOriginal                  map[string]string
	ReturnValuePreparedJsonpathQuery             map[string]jsonpath.FilterFunc
	ReturnValuePreparedJsonpathQueryRelativeFlag map[string]bool
	Node                                         Node                  `yaml:"condition,omitempty" json:"condition,omitempty" bson:"condition,omitempty" structs:"condition,omitempty"`
	PreparedJsonpathQuery                        []jsonpath.FilterFunc `yaml:"-,omitempty" json:"-,omitempty"`
}

func (a *All) MarshalJSON() ([]byte, error) {

	parentJsonpathAttributeString := a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal) > 0 {
		parentJsonpathAttributeString = a.ParentJsonpathAttributeOriginal
	}

	returnValueJsonpath := a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal) > 0 {
		returnValueJsonpath = a.ReturnValueJsonpathOriginal
	}

	str := fmt.Sprintf(`{"ALL":{"parentJsonpathAttribute":"%v",`, parentJsonpathAttributeString)
	if len(returnValueJsonpath) > 0 {
		returnValueJsonpathJson, _ := json.Marshal(returnValueJsonpath)
		str = fmt.Sprintf(`%v"returnValueJsonpath":%v,`, str, string(returnValueJsonpathJson))
	}

	conditionBytes, err := json.Marshal(a.Node)
	if err != nil {
		return []byte{}, err
	}
	str = fmt.Sprintf(`%v"condition":%v}}`, str, string(conditionBytes))

	return []byte(str), nil
}

func (a *All) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	if message.RequestRawInterface != nil && a.PreparedJsonpathQuery != nil {
		return evalAllRawInterface(a, message)
	} else {
		return evalAllRawBytes(a, message)
	}
}
func evalAllRawInterface(a *All, message *MessageAttributes) (bool, []map[string]interface{}) {

	rawArrayData, err := getArrayOfInterfaces(a, message)
	if err != nil {
		return false, []map[string]interface{}{}
	}

	originalRequestRawInterfaceRelative := message.RequestRawInterfaceRelative

	for _, val := range rawArrayData {
		message.RequestRawInterfaceRelative = &val
		flag, _ := a.Node.Eval(message)
		if !flag {

			message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
			return false, []map[string]interface{}{}

		}
	}
	message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
	return true, []map[string]interface{}{}

}

func evalAllRawBytes(a *All, message *MessageAttributes) (bool, []map[string]interface{}) {
	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false, []map[string]interface{}{}
	}

	originalRequestJsonRawRelative := message.RequestJsonRawRelative

	for _, val := range rawArrayData {
		message.RequestJsonRawRelative = &val
		flag, _ := a.Node.Eval(message)
		if !flag {
			message.RequestJsonRawRelative = originalRequestJsonRawRelative
			return false, []map[string]interface{}{}
		}
	}
	message.RequestJsonRawRelative = originalRequestJsonRawRelative
	return true, []map[string]interface{}{}
}

func (a *All) Append(node Node) {
	a.Node = node
}
func (a *All) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	err := a.Node.PrepareAndValidate(stringsAndlists)
	if err != nil {
		return err
	}

	a.ParentJsonpathAttributeArray = strings.Split(a.GetParentJsonpathAttribute(), ",")

	for _, j := range a.GetParentJsonpathAttributeArray() {
		preparedJsonpath, err := prepareJsonpathQuery(j)
		if err != nil {
			return err
		}
		a.PreparedJsonpathQuery = append(a.PreparedJsonpathQuery, preparedJsonpath)
	}

	return nil
}

func (a *All) String() string {
	str1 := a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal) > 0 {
		str1 = a.ParentJsonpathAttributeOriginal
	}
	str2 := a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal) > 0 {
		str2 = a.ReturnValueJsonpathOriginal
	}
	str := fmt.Sprintf("[ALL<%v;%v>:%v]", str1, str2, a.Node.String())
	return str
}

func (a *All) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.ParentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.ParentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *All) GetParentJsonpathAttribute() string {
	return a.ParentJsonpathAttribute
}

func (a *All) GetParentJsonpathAttributeArray() []string {
	return a.ParentJsonpathAttributeArray
}

func (a *All) SetReturnValueJsonpath(returnValueJsonpath map[string]string) {
	dc.Copy(&a.ReturnValueJsonpathOriginal, &returnValueJsonpath)
	dc.Copy(&a.ReturnValueJsonpath, &returnValueJsonpath)
	a.ReturnValuePreparedJsonpathQuery = make(map[string]jsonpath.FilterFunc)
	a.ReturnValuePreparedJsonpathQueryRelativeFlag = make(map[string]bool)
	for queryName, queryString := range returnValueJsonpath {
		a.ReturnValuePreparedJsonpathQueryRelativeFlag[queryName] = false
		if strings.HasPrefix(queryString, "jsonpath:$RELATIVE") {
			a.ReturnValuePreparedJsonpathQueryRelativeFlag[queryName] = true
		}
		a.ReturnValueJsonpath[queryName] = strings.Replace(queryString, "jsonpath:$RELATIVE", "$", 1)
		preparedQuery, err := prepareJsonpathQuery(a.ReturnValueJsonpath[queryName])
		if err == nil {
			a.ReturnValuePreparedJsonpathQuery[queryName] = preparedQuery
		} else {
			a.ReturnValuePreparedJsonpathQuery[queryName] = nil
		}

	}
}

func (a *All) GetReturnValueJsonpath() map[string]string {
	return a.ReturnValueJsonpathOriginal
}

func (a *All) GetPreparedJsonpathQuery() []jsonpath.FilterFunc {
	return a.PreparedJsonpathQuery
}

//--------------------------------------
// True Node (used in unit tests)
//--------------------------------------
type True struct{}

func (t True) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	return true, []map[string]interface{}{}
}
func (t True) Append(node Node) {
}
func (t True) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (t True) String() string {
	return "true"
}
func (t True) ToMongoQuery(base, str string, inArrayCounter int) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}

//--------------------------------------
// False Node (used in unit tests)
//--------------------------------------
type False struct{}

func (f False) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	return false, []map[string]interface{}{}
}
func (f False) Append(node Node) {
}
func (f False) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (f False) String() string {
	return "false"
}
func (f False) ToMongoQuery(base, str string, inArrayCounter int) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}

//--------------------------------------
// Basic Condition Node
//--------------------------------------
func (c *Condition) Eval(message *MessageAttributes) (bool, []map[string]interface{}) {
	return testOneCondition(c, message)
}
func (c *Condition) Append(node Node) {
}
func (c *Condition) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	err := ReplaceStringsAndListsInCondition(c, stringsAndlists)
	if err != nil {
		return err
	}
	valid, err := ValidateOneCondition(c)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("error in validating condition [%+v]", c)
	}

	err = ConvertConditionStringToIntFloatRegex(c)
	if err != nil {
		return err
	}

	if c.AttributeIsJsonpath {
		preparedJsonpath, err := prepareJsonpathQuery(c.AttributeJsonpathQuery)
		if err != nil {
			return err
		}
		c.PreparedJsonpathQuery = preparedJsonpath
	}

	return nil

}

//--------------------------------------
// parsing utilities
//--------------------------------------
func ParseConditionsTree(c interface{}) (Node, error) {

	conditionsTree, err := InterpretNode(c, "")
	if err != nil {
		return nil, err
	}

	return conditionsTree, nil
}

func InterpretNode(node interface{}, parentString string) (Node, error) {

	switch v := node.(type) {

	case map[string]interface{}:
		return handleMapStringInterface(v, parentString)

	case map[interface{}]interface{}:
		return handleMapInterfaceInterface(v, parentString)

	case []interface{}: // array of nodes
		if parentString == "" {
			if len(v) != 1 {
				return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
				//return nil, fmt.Errorf("can't parse conditions %+v", v)
			}
			return InterpretNode(v[0], "") // recursion
		} else {
			return handleInterfaceArray(node, parentString)
		}

	default:
		return nil, fmt.Errorf("can't parse conditions %+v", v)
	}
	return nil, errors.New("can't parse conditions")
}

func handleMapInterfaceInterface(v map[interface{}]interface{}, parentString string) (Node, error) {

	v2 := mapInterfaceToMapString(v)
	return handleMapStringInterface(v2, parentString)

}

func handleMapStringInterface(v2 map[string]interface{}, parentString string) (Node, error) {

	// test if this is a condition:
	if isConditionNode(v2) {
		nodeOut, err := getNodeCondition(v2, parentString)
		if err != nil {
			return nil, err
		} else {
			return nodeOut, nil
		}
	}

	// else it is supposed to be an AND, OR, ANY, ALL (etc) node:

	switch parentString {
	case "ANY", "ALL":
		anyAllNode, err := getAnyAllNode(v2, parentString)
		return anyAllNode, err
	case "NOT":
		notNode, err := getNotNode(v2, parentString)
		return notNode, err
	case "OR", "AND", "", "condition", "conditions", "conditionsTree":
		val, nodeType, err := getNodeValType(v2, parentString)
		if err != nil {
			return nil, err
		}
		node, err := InterpretNode(val, nodeType) // recursion!
		if err != nil {
			return nil, err
		}
		return node, nil
	default:
		return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
	}
	return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
}

func getNodeCondition(v map[string]interface{}, parentString string) (Node, error) {

	cond := ReadCondition(v)

	c, err := prepareOneConditionNode(cond) // add regexes etc... and validate the condition
	if err != nil {
		return nil, err
	}

	if parentString != "" && parentString != "condition" && parentString != "conditionsTree" { // add the condition to a AND,OR etc... Node
		nodes, err := getNodeByParentString(parentString)
		if err != nil {
			return nil, err
		}
		nodes.Append(c)
		return nodes, nil
	} else {
		return c, nil
	}
}

func isValidAnyAllNode(v map[string]interface{}) error {
	keys := getKeys(v)
	if len(keys) != 2 && len(keys) != 3 {
		return fmt.Errorf("map of size different than 2 or 3 [ANY/ALL node]")
	}
	if !slice.ContainsString(keys, "parentJsonpathAttribute") {
		return fmt.Errorf("ANY/ALL node without 'parentJsonpathAttribute' key")
	}
	return nil
}

func getAnyAllNode(v2 map[string]interface{}, parentString string) (Node, error) {

	err := isValidAnyAllNode(v2)
	if err != nil {
		return nil, err
	}

	var anyAllNode AnyAllNode //OOP
	if parentString == "ANY" {
		anyAllNode = &Any{}
	} else {
		anyAllNode = &All{}
	}

	for key, val := range v2 {
		switch key {
		case "parentJsonpathAttribute":
			parentJsonpathAttribute := val.(string)
			if isValidParentJsonpathAttribute(parentJsonpathAttribute) {
				anyAllNode.SetParentJsonpathAttribute(parentJsonpathAttribute)
			} else {
				return nil, fmt.Errorf("invalid parentJsonpathAttribute [%v]", parentJsonpathAttribute)
			}
		case "returnValueJsonpath":
			returnValueJsonpath := map[string]interface{}{}
			switch val.(type) {
			case map[string]interface{}:
				returnValueJsonpath = val.(map[string]interface{})
			case map[interface{}]interface{}:
				returnValueJsonpath = mapInterfaceToMapString(val.(map[interface{}]interface{}))
			default:
				return nil, fmt.Errorf("invalid returnValueJsonpath [%v is not map[string]interface]", val)
			}

			returnValueJsonpathMap := map[string]string{}
			for k, v := range returnValueJsonpath {
				vString := v.(string)
				if strings.HasPrefix(vString, "jsonpath:$RELATIVE") {
					returnValueJsonpathMap[k] = vString
				} else {
					return nil, fmt.Errorf("invalid returnValueJsonpath [%v] [should start with jsonpath:$RELATIVE]", returnValueJsonpath[k])
				}
				anyAllNode.SetReturnValueJsonpath(returnValueJsonpathMap)
			}
		default:
			node, err := InterpretNode(val, key) // recursion!
			if err != nil {
				return nil, err
			}
			anyAllNode.Append(node)
		}
	}
	if anyAllNode.GetParentJsonpathAttribute() == "" {
		return nil, fmt.Errorf("parentJsonpathAttribute is missing")
	}

	return anyAllNode, nil
}

func isValidNotNode(v map[string]interface{}) error {
	keys := getKeys(v)
	if len(keys) != 1 {
		return fmt.Errorf("map of size different than 1 [NOT node]")
	}
	return nil
}

func getNotNode(v2 map[string]interface{}, parentString string) (Node, error) {
	err := isValidNotNode(v2)
	if err != nil {
		return nil, err
	}
	val, nodeType, err := getNodeValType(v2, parentString)
	if err != nil {
		return nil, err
	}
	notNode := &Not{}
	nodeInner, err := InterpretNode(val, nodeType) // recursion!
	if err != nil {
		return nil, err
	}
	notNode.Append(nodeInner)
	return notNode, nil
}

func isValidParentJsonpathAttribute(parentJsonpathAttribute string) bool {
	flag1 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:.")
	flag2 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:$.")
	flag3 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:$RELATIVE")
	if !flag1 && !flag2 && !flag3 {
		return false
	}
	//if !strings.HasSuffix(parentJsonpathAttribute, "[:]") {
	//	return false
	//}
	return true
}

func mapInterfaceToMapString(node map[interface{}]interface{}) map[string]interface{} {
	node_out := make(map[string]interface{})
	for k, val := range node {
		node_out[k.(string)] = val
	}
	return node_out
}

func getNodeValType(node map[string]interface{}, parentString string) (interface{}, string, error) {

	keys := getKeys(node)
	if len(keys) != 1 {
		return nil, "", fmt.Errorf("map of size larger than 1 [node] %v", parentString)
	}
	key := keys[0]
	return node[key], key, nil

}

func prepareOneConditionNode(cond ConditionNode) (Node, error) {
	c := ConditionFromConditionNode(cond)
	valid, err := ValidateOneCondition(&c)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("error in validating condition [%+v]", cond)
	}

	return &c, nil
}

func handleInterfaceArray(node interface{}, parentString string) (Node, error) {
	v2 := node.([]interface{})
	nodes, err := getNodeByParentString(parentString)

	if err != nil {
		return nil, err
	}
	for _, subNode := range v2 {
		subNode2, err := InterpretNode(subNode, "") // recursion!
		if err != nil {
			return nil, fmt.Errorf("can't parse subNode [%+v]: %v", subNode, err)
		}
		nodes.Append(subNode2)
	}
	return nodes, nil
}

func getNodeByParentString(parentString string) (Node, error) {
	switch parentString {

	case "AND":
		return &And{}, nil

	case "OR":
		return &Or{}, nil

	case "NOT":
		return &Not{}, nil

	case "ANY", "ALL":
		return nil, fmt.Errorf("node of type ANY/ALL not according to spec")

	default:
		return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
	}
}
