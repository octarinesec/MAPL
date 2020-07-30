package MAPL_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bhmj/jsonslice"
	"sort"
	"strings"
)

//--------------------------------------
type Node interface {
	Eval(message *MessageAttributes) bool
	Append(node Node)
	String() string // to-do: order terms so that hash will be the same
}

type AnyAllNode interface {
	Eval(message *MessageAttributes) bool
	Append(node Node)
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

		// remove before release:
		if false {
			z := message.RequestJsonRawRelative
			if z != nil {
				fmt.Printf("%+v with %+v = %v\n", node.String(), string(*message.RequestJsonRawRelative), flag)
			} else {
				fmt.Printf("%+v with %+v = %v\n", node.String(), string(*message.RequestJsonRaw), flag)
			}
		}

		if flag == false {
			return false // no need to check the rest
		}
	}
	return true
}
func (a *And) Append(node Node) {
	a.nodes = append(a.nodes, node)
}

func (a *And) String() string {
	return AndOrString(a.nodes," && ")
}

func AndOrString(a_nodes []Node,andOrStr string)string {

	if len(a_nodes)==1{
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
func (o *Or) String() string {
	return AndOrString(o.nodes," || ")
}

//--------------------------------------
type Any struct {
	parentJsonpathAttribute string
	parentJsonpathAttributeOriginal string
	node                    Node
}

func (a *Any) Eval(message *MessageAttributes) bool { // to-do: return errors

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false
	}

	for _, val := range (rawArrayData) {
		message.RequestJsonRawRelative = &val
		flag := a.node.Eval(message)

		fmt.Printf("%+v with %+v = %v\n", a.String(), string(*message.RequestJsonRawRelative), flag)

		if flag {
			return true
		}
	}
	return false
}
func (a *Any) Append(node Node) {
	a.node = node
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
	if strings.HasPrefix(parentJsonpath, "$relative.") { // to-do: create a flag once when parsing!
		parentJsonpath = strings.Replace(parentJsonpath, "$relative.", "$.", -1)
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
	parentJsonpathAttribute string
	parentJsonpathAttributeOriginal string
	node                    Node
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
func (t False) String() string {
	return "false"
}

//--------------------------------------
func (c *Condition) Eval(message *MessageAttributes) bool {
	return testOneCondition(c, message)
}
func (c *Condition) Append(node Node) {
}
/*
func (c *Condition) String() string {
	//return c.String()
	return fmt.Sprintf("<%v-%v-%v>", c.OriginalAttribute, c.Method, c.Value)
}
*/