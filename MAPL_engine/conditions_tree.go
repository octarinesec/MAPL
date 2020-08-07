package MAPL_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhmj/jsonslice"
	"github.com/toolkits/slice"
	"sort"
	"strings"
)

type ConditionsTree struct {
	ConditionsTree Node
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

//--------------------------------------
type Node interface {
	Eval(message *MessageAttributes) bool
	Append(node Node)
	PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error
	String() string // to-do: order terms so that hash will be the same
}

type AnyAllNode interface {
	Eval(message *MessageAttributes) bool
	Append(node Node)
	PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error
	String() string
	SetParentJsonpathAttribute(parentJsonpathAttribute string)
	GetParentJsonpathAttribute() string
}

//--------------------------------------
type And struct {
	nodes []Node
}

func (a *And) Eval(message *MessageAttributes) bool {
	for _, node := range a.nodes {
		flag := node.Eval(message)
		if flag == false {
			return false // no need to check the rest
		}
	}
	return true
}
func (a *And) Append(node Node) {
	a.nodes = append(a.nodes, node)
}

func (a *And) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	for _, node := range a.nodes {
		err := node.PrepareAndValidate(stringsAndlists)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *And) String() string {
	return AndOrString(a.nodes, " && ")
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
type Or struct {
	nodes []Node
}

func (o *Or) Eval(message *MessageAttributes) bool {
	for _, node := range o.nodes {
		flag := node.Eval(message)
		if flag {
			return true // no need to check the rest
		}
	}
	return false
}
func (o *Or) Append(node Node) {
	o.nodes = append(o.nodes, node)
}
func (o *Or) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	for _, node := range o.nodes {
		err := node.PrepareAndValidate(stringsAndlists)
		if err != nil {
			return err
		}
	}
	return nil
}
func (o *Or) String() string {
	return AndOrString(o.nodes, " || ")
}

//--------------------------------------
type Any struct {
	parentJsonpathAttribute         string
	parentJsonpathAttributeOriginal string
	node                            Node
}

func (a *Any) Eval(message *MessageAttributes) bool { // to-do: return errors

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false
	}

	for _, val := range (rawArrayData) {
		message.RequestJsonRawRelative = &val
		flag := a.node.Eval(message)
		if flag {
			return true
		}
	}
	return false
}
func (a *Any) Append(node Node) {
	a.node = node
}
func (a *Any) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {

	err := a.node.PrepareAndValidate(stringsAndlists)
	if err != nil {
		return err
	}

	return nil
}

func (a *Any) String() string {
	str := fmt.Sprintf("[ANY<%v>:%v]", a.parentJsonpathAttributeOriginal, a.node.String())
	return str
}

func (a *Any) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.parentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.parentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *Any) GetParentJsonpathAttribute() string {
	return a.parentJsonpathAttribute
}

func getArrayOfJsons(a AnyAllNode, message *MessageAttributes) ([][]byte, error) {

	arrayData := []byte{}
	err := errors.New("error")
	parentJsonpath := a.GetParentJsonpathAttribute()
	if strings.HasPrefix(parentJsonpath, "$RELATIVE.") { // to-do: create a flag once when parsing!
		parentJsonpath = strings.Replace(parentJsonpath, "$RELATIVE.", "$.", 1)
		arrayData, err = jsonslice.Get(*message.RequestJsonRawRelative, parentJsonpath)
	} else {
		arrayData, err = jsonslice.Get(*message.RequestJsonRaw, parentJsonpath)
	}

	if err != nil {
		return [][]byte{}, err
	}

	var arrayInterface []interface{}
	arrayJson := [][]byte{}
	err = json.Unmarshal([]byte(arrayData), &arrayInterface)
	if err != nil {
		return [][]byte{}, err
	}
	for _, x := range (arrayInterface) {
		y, err := json.Marshal(x)
		if err != nil {
			return [][]byte{}, err
		}
		arrayJson = append(arrayJson, y)
	}
	return arrayJson, nil
}

//--------------------------------------
type All struct {
	parentJsonpathAttribute         string
	parentJsonpathAttributeOriginal string
	node                            Node
}

func (a *All) Eval(message *MessageAttributes) bool {

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false
	}

	for _, val := range (rawArrayData) {
		message.RequestJsonRawRelative = &val
		flag := a.node.Eval(message)
		if !flag {
			return false
		}
	}
	return true
}
func (a *All) Append(node Node) {
	a.node = node
}
func (a *All) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	err := a.node.PrepareAndValidate(stringsAndlists)
	if err != nil {
		return err
	}
	return nil
}

func (a *All) String() string {
	str := fmt.Sprintf("[ALL<%v>:%v]", a.parentJsonpathAttributeOriginal, a.node.String())
	return str
}

func (a *All) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.parentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.parentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *All) GetParentJsonpathAttribute() string {
	return a.parentJsonpathAttribute
}

//--------------------------------------
type True struct{}

func (t True) Eval(message *MessageAttributes) bool {
	return true
}
func (t True) Append(node Node) {
}
func (t True) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (t True) String() string {
	return "true"
}

//--------------------------------------
type False struct{}

func (f False) Eval(message *MessageAttributes) bool {
	return false
}
func (f False) Append(node Node) {
}
func (f False) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (t False) String() string {
	return "false"
}

//--------------------------------------
func (c *Condition) Eval(message *MessageAttributes) bool {
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

	err = ConvertConditionStringToIntFloatRegexV2(c)
	if err != nil {
		return err
	}
	return nil

}

/*
func (c *Condition) String() string {
	//return c.String()
	return fmt.Sprintf("<%v-%v-%v>", c.OriginalAttribute, c.Method, c.Value)
}
*/

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

	case map[interface{}]interface{}:
		return handleMapInterfaceInterface(v, parentString)

	case []interface{}: // array of nodes
		return handleInterfaceArray(node, parentString)

	default:
		return nil, fmt.Errorf("can't parse conditions %+v", v)
	}
	return nil, errors.New("can't parse conditions")
}

func handleMapInterfaceInterface(v map[interface{}]interface{}, parentString string) (Node, error) {

	v2 := mapInterfaceToMapString(v)
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
	default:
		val, nodeType, err := getNodeValType(v2, parentString)
		if err != nil {
			return nil, err
		}
		node, err := InterpretNode(val, nodeType) // recursion!
		if err != nil {
			return nil, err
		}
		return node, nil

	}
	return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
}

func getNodeCondition(v map[string]interface{}, parentString string) (Node, error) {

	cond := ReadCondition(v)

	c, err := prepareOneConditionNode(cond) // add regexes etc... and validate the condition
	if err != nil {
		return nil, err
	}
	if parentString != "" && parentString != "condition" { // add the condition to a AND,OR etc... Node
		nodes, err := getNodeByParentString(parentString)
		if err != nil {
			return nil, err
		}
		nodes.Append(c)
		return nodes, nil
	} else { // just return the node
		return c, nil
	}
}

func getAnyAllNode(v2 map[string]interface{}, parentString string) (Node, error) {

	keys := getKeys(v2)
	if len(keys) != 2 {
		return nil, fmt.Errorf("map of size different than 2 [ANY/ALL node]")
	}
	if !slice.ContainsString(keys, "parentJsonpathAttribute") {
		return nil, fmt.Errorf("ANY/ALL node without 'parentJsonpathAttribute' key")
	}

	var anyAllNode AnyAllNode //OOP
	if parentString == "ANY" {
		anyAllNode = &Any{}
	} else {
		anyAllNode = &All{}
	}

	for key, val := range (v2) {
		if key == "parentJsonpathAttribute" {
			parentJsonpathAttribute := val.(string)
			if isValidParentJsonpathAttribute(parentJsonpathAttribute) {
				anyAllNode.SetParentJsonpathAttribute(parentJsonpathAttribute)
			} else {
				return nil, fmt.Errorf("invalid parentJsonpathAttribute [%v]", parentJsonpathAttribute)
			}
		} else {
			node, err := InterpretNode(val, key) // recursion!
			if err != nil {
				return nil, err
			}
			anyAllNode.Append(node)
		}
	}
	return anyAllNode, nil
}

func isValidParentJsonpathAttribute(parentJsonpathAttribute string) bool {
	flag1 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:.")
	flag2 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:$.")
	flag3 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:$RELATIVE.")
	if !flag1 && !flag2 && !flag3 {
		return false
	}
	if !strings.HasSuffix(parentJsonpathAttribute, "[:]") {
		return false
	}
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
	/*
		err = ConvertConditionStringToIntFloatRegexV2(&c)
		if err != nil {
			return nil, err
		}
	*/
	return &c, nil
}

func handleInterfaceArray(node interface{}, parentString string) (Node, error) {
	v2 := node.([]interface{})
	nodes, err := getNodeByParentString(parentString)

	if err != nil {
		return nil, err
	}
	for _, subNode := range (v2) {
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

	case "ANY", "ALL":
		return nil, fmt.Errorf("node of type ANY/ALL not according to spec")

	default:
		return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
	}
}
