package MAPL_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhmj/jsonslice"
	"github.com/globalsign/mgo/bson"
	"github.com/toolkits/slice"
	"sort"
	"strings"


)

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
	/*dataYaml,err:=ghodssYaml.JSONToYAML(data)
	if err!=nil{
		return nil
	}
	fmt.Println(string(dataYaml))
	err=yaml.Unmarshal(dataYaml,&r)
	return err
	*/
	//fmt.Println("MarshalJSON is overriden")

	if len(data) == 2 {
		if data[0] == 123 && data[1] == 125 {
			c.ConditionsTree = nil
			return nil
		}
	}

	var aux interface{}
	if err := json.Unmarshal(data,&aux); err != nil {
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
	Eval(message *MessageAttributes) (bool, string)
	Append(node Node)
	PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error
	String() string // to-do: order terms so that hash will be the same
	ToMongoQuery(parentString string) (bson.M, []bson.M, error)
}

type AnyAllNode interface {
	//Eval(message *MessageAttributes) (bool, string)
	//Append(node Node)
	//PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error
	//String() string
	Node
	SetParentJsonpathAttribute(parentJsonpathAttribute string)
	GetParentJsonpathAttribute() string
	SetReturnValueJsonpath(returnValueJsonpath string)
	GetReturnValueJsonpath() string
	//ToMongoQuery(parentString string) (bson.M, []bson.M, error)
}

//--------------------------------------
type And struct {
	Nodes []Node `yaml:"AND,omitempty" json:"AND,omitempty" bson:"AND,omitempty" structs:"AND,omitempty"`
}

func (a *And) Eval(message *MessageAttributes) (bool, string) {
	extraData := ""
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
type Or struct {
	Nodes []Node `yaml:"OR,omitempty" json:"OR,omitempty" bson:"OR,omitempty" structs:"OR,omitempty"`
}

func (o *Or) Eval(message *MessageAttributes) (bool, string) {
	extraData := ""
	for _, node := range o.Nodes {
		flag, extraData := node.Eval(message)
		if flag {
			return true, extraData // no need to check the rest
		}
	}
	return false, extraData
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
type Not struct {
	Node Node `yaml:"NOT,omitempty" json:"NOT,omitempty" bson:"NOT,omitempty" structs:"NOT,omitempty"`
}

func (n *Not) Eval(message *MessageAttributes) (bool, string) {
	flag, _ := n.Node.Eval(message)
	return !flag, ""
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

type Any struct {
	ParentJsonpathAttribute         string
	ParentJsonpathAttributeOriginal string
	ReturnValueJsonpath             string
	ReturnValueJsonpathOriginal     string
	Node                            Node `yaml:"condition,omitempty" json:"condition,omitempty" bson:"condition,omitempty" structs:"condition,omitempty"`
}

func (a *Any) MarshalJSON() ([]byte, error){

	parentJsonpathAttributeString:=a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal)>0{
		parentJsonpathAttributeString=a.ParentJsonpathAttributeOriginal
	}

	returnValueJsonpath:=a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal)>0{
		returnValueJsonpath=a.ReturnValueJsonpathOriginal
	}

	str:=fmt.Sprintf(`{"ANY":{"parentJsonpathAttribute":"%v",`,parentJsonpathAttributeString)
	if len(returnValueJsonpath)>0{
		str=fmt.Sprintf(`%v"returnValueJsonpath":"%v",`,str,returnValueJsonpath)
	}

	conditionBytes,err:=json.Marshal(a.Node)
	if err!=nil{
		return []byte{},err
	}
	str=fmt.Sprintf(`%v"condition":%v}}`,str,string(conditionBytes))

	return []byte(str), nil
}

func (a *Any) Eval(message *MessageAttributes) (bool, string) { // to-do: return errors

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false, ""
	}

	extraData := ""
	result := false
	checkAllValuesInTheArray := false
	if len(a.ReturnValueJsonpath) > 0 {
		checkAllValuesInTheArray = true
	}
	for _, val := range (rawArrayData) {
		message.RequestJsonRawRelative = &val
		flag, _ := a.Node.Eval(message)
		extraDataBytes, _ := jsonslice.Get(val, a.ReturnValueJsonpath)
		extraDataTemp := string(extraDataBytes)
		extraDataTemp, _ = removeQuotes(extraDataTemp)
		if flag {
			result = true
			extraData += extraDataTemp + ","
			if !checkAllValuesInTheArray {
				return true, extraDataTemp
			}
		}
	}
	if strings.HasSuffix(extraData, ",") {
		extraData = extraData[0 : len(extraData)-1]
	}
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

	return nil
}

func (a *Any) String() string {
	str := fmt.Sprintf("[ANY<%v>:%v]", a.ParentJsonpathAttributeOriginal, a.Node.String())
	return str
}

func (a *Any) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.ParentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.ParentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *Any) GetParentJsonpathAttribute() string {
	return a.ParentJsonpathAttribute
}

func (a *Any) SetReturnValueJsonpath(returnValueJsonpath string) {
	a.ReturnValueJsonpathOriginal = returnValueJsonpath
	//a.ReturnValueJsonpath = strings.Replace(returnValueJsonpath, "jsonpath:", "", -1)
	a.ReturnValueJsonpath = strings.Replace(returnValueJsonpath, "jsonpath:$RELATIVE.", "$.", 1)
}

func (a *Any) GetReturnValueJsonpath() string {
	return a.ReturnValueJsonpathOriginal
}

func getArrayOfJsons(a AnyAllNode, message *MessageAttributes) ([][]byte, error) {

	arrayData := []byte{}
	err := errors.New("error")
	parentJsonpath := a.GetParentJsonpathAttribute()
	if strings.HasPrefix(parentJsonpath, "$RELATIVE.") || strings.HasPrefix(parentJsonpath, "$KEY.") || strings.HasPrefix(parentJsonpath, "$VALUE.") { // to-do: create a flag once when parsing!
		parentJsonpath = strings.Replace(parentJsonpath, "$RELATIVE.", "$.", 1)
		parentJsonpath = strings.Replace(parentJsonpath, "$KEY.", "$.", 1)
		parentJsonpath = strings.Replace(parentJsonpath, "$VALUE.", "$.", 1)
		arrayData, err = jsonslice.Get(*message.RequestJsonRawRelative, parentJsonpath)
	} else {
		arrayData, err = jsonslice.Get(*message.RequestJsonRaw, parentJsonpath)
	}

	if err != nil {
		return [][]byte{}, err
	}

	arrayJson, err := getArrayOfJsonsFromInterfaceArray(arrayData)
	if err != nil {
		arrayJson, err := getArrayOfJsonsFromMapStringInterface(arrayData)
		if err != nil {
			return [][]byte{}, err
		}
		return arrayJson, nil
	}
	return arrayJson, nil
}

func getArrayOfJsonsFromInterfaceArray(arrayData []byte) ([][]byte, error) {
	var arrayInterface []interface{}
	arrayJson := [][]byte{}
	err := json.Unmarshal([]byte(arrayData), &arrayInterface)
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

func getArrayOfJsonsFromMapStringInterface(arrayData []byte) ([][]byte, error) {
	var arrayInterface map[string]interface{}
	arrayJson := [][]byte{}
	err := json.Unmarshal([]byte(arrayData), &arrayInterface)
	if err != nil {
		return [][]byte{}, err
	}
	for i_x, x := range (arrayInterface) {
		z := map[string]interface{}{}
		z[i_x] = x
		y, err := json.Marshal(z)
		if err != nil {
			return [][]byte{}, err
		}
		arrayJson = append(arrayJson, y)
	}
	return arrayJson, nil
}

//--------------------------------------
type All struct {
	ParentJsonpathAttribute         string
	ParentJsonpathAttributeOriginal string
	ReturnValueJsonpath             string
	ReturnValueJsonpathOriginal     string
	Node                            Node `yaml:"condition,omitempty" json:"condition,omitempty" bson:"condition,omitempty" structs:"condition,omitempty"`
}


func (a *All) MarshalJSON() ([]byte, error){

	parentJsonpathAttributeString:=a.ParentJsonpathAttribute
	if len(a.ParentJsonpathAttributeOriginal)>0{
		parentJsonpathAttributeString=a.ParentJsonpathAttributeOriginal
	}

	returnValueJsonpath:=a.ReturnValueJsonpath
	if len(a.ReturnValueJsonpathOriginal)>0{
		returnValueJsonpath=a.ReturnValueJsonpathOriginal
	}

	str:=fmt.Sprintf(`{"ALL":{"parentJsonpathAttribute":"%v",`,parentJsonpathAttributeString)
	if len(returnValueJsonpath)>0{
		str=fmt.Sprintf(`%v"returnValueJsonpath":"%v",`,str,returnValueJsonpath)
	}

	conditionBytes,err:=json.Marshal(a.Node)
	if err!=nil{
		return []byte{},err
	}
	str=fmt.Sprintf(`%v"condition":%v}}`,str,string(conditionBytes))

	return []byte(str), nil
}

func (a *All) Eval(message *MessageAttributes) (bool, string) {

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false, ""
	}

	for _, val := range (rawArrayData) {
		message.RequestJsonRawRelative = &val
		flag, _ := a.Node.Eval(message)
		if !flag {
			return false, ""
		}
	}
	return true, ""
}
func (a *All) Append(node Node) {
	a.Node = node
}
func (a *All) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	err := a.Node.PrepareAndValidate(stringsAndlists)
	if err != nil {
		return err
	}
	return nil
}

func (a *All) String() string {
	str := fmt.Sprintf("[ALL<%v>:%v]", a.ParentJsonpathAttributeOriginal, a.Node.String())
	return str
}

func (a *All) SetParentJsonpathAttribute(parentJsonpathAttribute string) {
	a.ParentJsonpathAttributeOriginal = parentJsonpathAttribute
	a.ParentJsonpathAttribute = strings.Replace(parentJsonpathAttribute, "jsonpath:", "", -1)
}

func (a *All) GetParentJsonpathAttribute() string {
	return a.ParentJsonpathAttribute
}

func (a *All) SetReturnValueJsonpath(returnValueJsonpath string) {
	a.ReturnValueJsonpathOriginal = returnValueJsonpath
	//a.ReturnValueJsonpath = strings.Replace(returnValueJsonpath, "jsonpath:", "", -1)
	a.ReturnValueJsonpath = strings.Replace(returnValueJsonpath, "jsonpath:$RELATIVE.", "$.", 1)

}

func (a *All) GetReturnValueJsonpath() string {
	return a.ReturnValueJsonpathOriginal
}

//--------------------------------------
type True struct{}

func (t True) Eval(message *MessageAttributes) (bool, string) {
	return true, ""
}
func (t True) Append(node Node) {
}
func (t True) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (t True) String() string {
	return "true"
}
func (t True) ToMongoQuery(str string) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}

//--------------------------------------
type False struct{}

func (f False) Eval(message *MessageAttributes) (bool, string) {
	return false, ""
}
func (f False) Append(node Node) {
}
func (f False) PrepareAndValidate(stringsAndlists PredefinedStringsAndLists) error {
	return nil
}
func (f False) String() string {
	return "false"
}
func (f False) ToMongoQuery(str string) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}

//--------------------------------------
func (c *Condition) Eval(message *MessageAttributes) (bool, string) {
	return testOneCondition(c, message), ""
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

	case map[string]interface{}:
		return handleMapStringInterface(v, parentString)

	case map[interface{}]interface{}:
		return handleMapInterfaceInterface(v, parentString)

	case []interface{}: // array of nodes
		if parentString==""{
			if len(v)!=1{
				return nil, fmt.Errorf("can't parse conditions %+v", v)
			}
			return InterpretNode(v[0],"")
		}else {
			return handleInterfaceArray(node, parentString)
		}

	default:
		return nil, fmt.Errorf("can't parse conditions %+v", v)
	}
	return nil, errors.New("can't parse conditions")
}

func handleMapInterfaceInterface(v map[interface{}]interface{}, parentString string) (Node, error) {

	v2 := mapInterfaceToMapString(v)
	return handleMapStringInterface(v2,parentString)

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


	if parentString != "" && parentString != "condition" && parentString != "conditionsTree" { // add the condition to a AND,OR etc... Node
		nodes, err := getNodeByParentString(parentString)
		if err != nil {
			return nil, err
		}
		nodes.Append(c)
		return nodes, nil
	} else {
		if parentString == "conditionsTree"{
			return c,nil
		}else { // just return the node
			return c, nil
		}
	}
}

func getAnyAllNode(v2 map[string]interface{}, parentString string) (Node, error) {

	keys := getKeys(v2)
	if len(keys) != 2 && len(keys) != 3 {
		return nil, fmt.Errorf("map of size different than 2 or 3 [ANY/ALL node]")
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
		switch (key) {
		case "parentJsonpathAttribute":
			parentJsonpathAttribute := val.(string)
			if isValidParentJsonpathAttribute(parentJsonpathAttribute) {
				anyAllNode.SetParentJsonpathAttribute(parentJsonpathAttribute)
			} else {
				return nil, fmt.Errorf("invalid parentJsonpathAttribute [%v]", parentJsonpathAttribute)
			}
		case "returnValueJsonpath":
			returnValueJsonpath := val.(string)
			if strings.HasPrefix(returnValueJsonpath, "jsonpath:$RELATIVE.") {
				anyAllNode.SetReturnValueJsonpath(returnValueJsonpath)
			} else {
				return nil, fmt.Errorf("invalid returnValueJsonpath [%v] [should start with jsonpath:$RELATIVE.]", returnValueJsonpath)
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

func getNotNode(v2 map[string]interface{}, parentString string) (Node, error) {

	keys := getKeys(v2)
	if len(keys) != 1 {
		return nil, fmt.Errorf("map of size different than 1 [NOT node]")
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
	flag3 := strings.HasPrefix(parentJsonpathAttribute, "jsonpath:$RELATIVE.")
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

	case "NOT":
		return &Not{}, nil

	case "ANY", "ALL":
		return nil, fmt.Errorf("node of type ANY/ALL not according to spec")

	default:
		return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
	}
}
