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

// -----------------------
// ConditionsTree
// -----------------------
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

// --------------------------------------
// Node Interface
// --------------------------------------
type Node interface {
	Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool
	Append(node Node)
	PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error)
	String() string // to-do: order terms so that hash will be the same
	ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error)
	ResetVariables()
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

// --------------------------------------
func mergeReturnValues(returnValues *map[string][]interface{}, returnValues2 *map[string][]interface{}) {
	for key, array2 := range *returnValues2 {
		if array, ok := (*returnValues)[key]; !ok {
			(*returnValues)[key] = array2
		} else {
			array = append(array, array2...)
			(*returnValues)[key] = array
		}
	}

}

// --------------------------------------
// And Node
// --------------------------------------
type And struct {
	Nodes             []Node `yaml:"AND,omitempty" json:"AND,omitempty" bson:"AND,omitempty" structs:"AND,omitempty"`
	ReturnValueInNode bool   `yaml:"-" json:"-" bson:"-" structs:"-"`
}

func (a *And) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool {

	returnValuesAfter := make(map[string][]interface{}) // we use temporary return values since we do not want to update them unless the AND result is true
	returnValuesBefore := make(map[string][]interface{})
	mergeReturnValues(&returnValuesAfter, returnValues)
	mergeReturnValues(&returnValuesBefore, returnValues)

	for _, node := range a.Nodes {

		flag := node.Eval(message, &returnValuesAfter)

		if flag == false {
			// clean previous map and enter new values. to-do: find a better way.
			for k := range *returnValues {
				delete(*returnValues, k)
			}
			mergeReturnValues(returnValues, &returnValuesBefore)
			return false // no need to check the rest
		}

	}

	// clean previous map and enter new values. to-do: find a better way
	for k := range *returnValues {
		delete(*returnValues, k)
	}
	mergeReturnValues(returnValues, &returnValuesAfter)

	return true
}
func (a *And) Append(node Node) {
	a.Nodes = append(a.Nodes, node)
}

func (a *And) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {
	returnValuesInNode := false
	for _, node := range a.Nodes {
		returnValuesInNodeTemp, err := node.PrepareAndValidate(listOfVariables, stringsAndlists)
		if returnValuesInNodeTemp {
			returnValuesInNode = true
		}
		if err != nil {
			return returnValuesInNode, err
		}
	}
	a.ReturnValueInNode = returnValuesInNode
	return returnValuesInNode, nil
}

func (a *And) String() string {
	return AndOrString(a.Nodes, " && ")
}

func (a *And) ResetVariables() {

	for _, node := range a.Nodes {
		node.ResetVariables()
	}
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

// --------------------------------------
// Or Node
// --------------------------------------
type Or struct {
	Nodes             []Node `yaml:"OR,omitempty" json:"OR,omitempty" bson:"OR,omitempty" structs:"OR,omitempty"`
	ReturnValueInNode bool   `yaml:"-" json:"-" bson:"-" structs:"-"`
}

func (o *Or) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool {
	flagOut := false
	for _, node := range o.Nodes {
		returnValuesTemp := make(map[string][]interface{})
		flag := node.Eval(message, &returnValuesTemp)
		if flag && !o.ReturnValueInNode {
			return true // no need to check the rest if we do not need to extract return values
		}
		flagOut = flagOut || flag
		if flag {
			mergeReturnValues(returnValues, &returnValuesTemp)
		}
	}
	return flagOut
}
func (o *Or) Append(node Node) {
	o.Nodes = append(o.Nodes, node)
}
func (o *Or) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {
	returnValuesInNode := false
	for _, node := range o.Nodes {
		returnValuesInNodeTemp, err := node.PrepareAndValidate(listOfVariables, stringsAndlists)
		if returnValuesInNodeTemp {
			returnValuesInNode = true
		}
		if err != nil {
			return false, err
		}
	}
	o.ReturnValueInNode = returnValuesInNode
	return returnValuesInNode, nil
}
func (o *Or) String() string {
	return AndOrString(o.Nodes, " || ")
}

func (o *Or) ResetVariables() {
	for _, node := range o.Nodes {
		node.ResetVariables()
	}
}

// --------------------------------------
// Not Node
// --------------------------------------
type Not struct {
	Node              Node `yaml:"NOT,omitempty" json:"NOT,omitempty" bson:"NOT,omitempty" structs:"NOT,omitempty"`
	ReturnValueInNode bool `yaml:"-" json:"-" bson:"-" structs:"-"`
}

func (n *Not) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool {
	flag := n.Node.Eval(message, returnValues)
	(*returnValues) = nil // returned values from inner nodes are no-longer relevant!
	return !flag
}
func (n *Not) Append(node Node) {
	n.Node = node
}
func (n *Not) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {

	returnValuesInNode, err := n.Node.PrepareAndValidate(listOfVariables, stringsAndlists)
	n.ReturnValueInNode = returnValuesInNode
	return returnValuesInNode, err

}
func (n *Not) String() string {
	str := fmt.Sprintf("!(%v)", n.Node.String())
	return str
}
func (n *Not) ResetVariables() {

	n.ResetVariables()

}

// --------------------------------------
// Any Node
// --------------------------------------
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
	ReturnValueInNode                            bool                  `yaml:"-" json:"-" bson:"-" structs:"-"`
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

func (a *Any) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool { // to-do: return errors
	if message.RequestRawInterface != nil && a.PreparedJsonpathQuery != nil {
		return evalAnyRawInterface(a, message, returnValues)
	} else {
		return evalAnyRawBytes(a, message, returnValues)
	}
}

func evalAnyRawInterface(a *Any, message *MessageAttributes, returnValues *map[string][]interface{}) bool {

	rawArrayData, err := getArrayOfInterfaces(a, message)
	if err != nil {
		return false
	}

	//extraData := []map[string]interface{}{}
	result := false
	checkAllValuesInTheArray := false
	if a.ReturnValueInNode { // if we seek return values in sub-nodes then we cannot skip
		checkAllValuesInTheArray = true
	}
	originalRequestRawInterfaceRelative := message.RequestRawInterfaceRelative
	for _, val := range rawArrayData {
		message.RequestRawInterfaceRelative = &val
		flag := a.Node.Eval(message, returnValues)
		if flag {
			result = true
			if a.ReturnValueJsonpath != nil {

				getExtraDataFromInterface(a.ReturnValuePreparedJsonpathQuery, a.ReturnValuePreparedJsonpathQueryRelativeFlag, a.ReturnValueJsonpath, message, returnValues)
				//extraData = append(extraData, extraDataTemp)

			}
			if !checkAllValuesInTheArray {
				message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
				return result
			}
		}
	}

	message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
	return result
}
func evalAnyRawBytes(a *Any, message *MessageAttributes, returnValues *map[string][]interface{}) bool {

	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false
	}

	//extraData := []map[string]interface{}{}
	result := false
	checkAllValuesInTheArray := false
	if a.ReturnValueInNode { // if we seek return values in sub-nodes then we cannot skip
		checkAllValuesInTheArray = true
	}
	originalRequestJsonRawRelative := message.RequestJsonRawRelative
	//	fmt.Printf("ANY: ---------\n")

	for _, val := range rawArrayData {
		message.RequestJsonRawRelative = &val
		flag := a.Node.Eval(message, returnValues)
		//		fmt.Printf("ANY: flag=%v,node=%v\n", flag, a.String())
		if flag {
			result = true
			if a.ReturnValueJsonpath != nil { // this is for the ANY node returnValue
				getExtraDataFromByteArray(a.ReturnValueJsonpath, a.ReturnValuePreparedJsonpathQueryRelativeFlag, message, returnValues)
				//extraData = append(extraData, extraDataTemp)
			}
			if !checkAllValuesInTheArray {
				message.RequestJsonRawRelative = originalRequestJsonRawRelative
				return result
			}
		}
	}

	message.RequestJsonRawRelative = originalRequestJsonRawRelative
	return result
}
func (a *Any) Append(node Node) {
	a.Node = node
}
func (a *Any) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {

	returnValuesInNode, err := a.Node.PrepareAndValidate(listOfVariables, stringsAndlists)
	if err != nil {
		return false, err
	}

	for k, _ := range a.ReturnValueJsonpath { // this is the list of variables currently available at this node:
		*listOfVariables = append(*listOfVariables, "#"+k)
	}

	a.ParentJsonpathAttributeArray = strings.Split(a.GetParentJsonpathAttribute(), ",")

	for _, j := range a.GetParentJsonpathAttributeArray() {
		preparedJsonpath, err := prepareJsonpathQuery(j)
		if err != nil {
			return false, err
		}
		a.PreparedJsonpathQuery = append(a.PreparedJsonpathQuery, preparedJsonpath)
	}

	if len(a.ReturnValueJsonpath) > 0 {
		returnValuesInNode = true
	}
	a.ReturnValueInNode = returnValuesInNode
	return returnValuesInNode, nil
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

func (a *Any) ResetVariables() {

	a.Node.ResetVariables()

}

// --------------------------------------
// All Node
// --------------------------------------
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
	ReturnValueInNode                            bool                  `yaml:"-" json:"-" bson:"-" structs:"-"`
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

func (a *All) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool {
	if message.RequestRawInterface != nil && a.PreparedJsonpathQuery != nil {
		return evalAllRawInterface(a, message, returnValues)
	} else {
		return evalAllRawBytes(a, message, returnValues)
	}
}
func evalAllRawInterface(a *All, message *MessageAttributes, returnValues *map[string][]interface{}) bool {

	rawArrayData, err := getArrayOfInterfaces(a, message)
	if err != nil {
		return false
	}

	originalRequestRawInterfaceRelative := message.RequestRawInterfaceRelative

	for _, val := range rawArrayData {
		message.RequestRawInterfaceRelative = &val
		flag := a.Node.Eval(message, returnValues)
		if !flag {

			message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
			return false

		}
	}
	message.RequestRawInterfaceRelative = originalRequestRawInterfaceRelative
	return true

}

func evalAllRawBytes(a *All, message *MessageAttributes, returnValues *map[string][]interface{}) bool {
	rawArrayData, err := getArrayOfJsons(a, message)
	if err != nil {
		return false
	}

	originalRequestJsonRawRelative := message.RequestJsonRawRelative

	for _, val := range rawArrayData {
		message.RequestJsonRawRelative = &val
		flag := a.Node.Eval(message, returnValues)
		if !flag {
			message.RequestJsonRawRelative = originalRequestJsonRawRelative
			return false
		}
	}
	message.RequestJsonRawRelative = originalRequestJsonRawRelative
	return true
}

func (a *All) Append(node Node) {
	a.Node = node
}
func (a *All) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {

	returnValuesInNode, err := a.Node.PrepareAndValidate(listOfVariables, stringsAndlists)
	if err != nil {
		return false, err
	}

	for k, _ := range a.ReturnValueJsonpath { // this is the list of variables currently available at this node:
		*listOfVariables = append(*listOfVariables, "#"+k)
	}

	a.ParentJsonpathAttributeArray = strings.Split(a.GetParentJsonpathAttribute(), ",")

	for _, j := range a.GetParentJsonpathAttributeArray() {
		preparedJsonpath, err := prepareJsonpathQuery(j)
		if err != nil {
			return false, err
		}
		a.PreparedJsonpathQuery = append(a.PreparedJsonpathQuery, preparedJsonpath)
	}

	if len(a.ReturnValueJsonpath) > 0 {
		returnValuesInNode = true
	}
	a.ReturnValueInNode = returnValuesInNode

	return returnValuesInNode, nil
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

func (a *All) ResetVariables() {
	a.Node.ResetVariables()
}

// --------------------------------------
// True Node (used in unit tests)
// --------------------------------------
type True struct{}

func (t True) Eval(message *MessageAttributes, _ *map[string][]interface{}) bool {
	return true
}
func (t True) Append(node Node) {
}
func (t True) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {
	return false, nil
}
func (t True) String() string {
	return "true"
}
func (t True) ToMongoQuery(base, str string, inArrayCounter int) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}
func (t True) ResetVariables() {
}

// --------------------------------------
// False Node (used in unit tests)
// --------------------------------------
type False struct{}

func (f False) Eval(message *MessageAttributes, _ *map[string][]interface{}) bool {
	return false
}
func (f False) Append(node Node) {
}
func (f False) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {
	return false, nil
}
func (f False) String() string {
	return "false"
}
func (f False) ToMongoQuery(base, str string, inArrayCounter int) (bson.M, []bson.M, error) {
	return bson.M{}, []bson.M{}, fmt.Errorf("not supported")
}
func (f False) ResetVariables() {
}

// --------------------------------------
// Basic Condition Node
// --------------------------------------
func (c *Condition) Eval(message *MessageAttributes, returnValues *map[string][]interface{}) bool {

	if c.ValueContainsVariable && returnValues != nil {

		c.OriginalAttributeWithVariables = c.Attribute
		c.OriginalMethodWithVariables = c.Method
		c.OriginalValueWithVariables = c.Value
		c.OriginalValueContainsVariable = c.ValueContainsVariable

		replaceVariableWithReturnValues(c, returnValues)
	}

	if c.ValueContainsVariable { // since the variable was not filled with data in runtime
		return false
	}

	return testOneCondition(c, message, returnValues) // we do not automatically update the returnValuesForVariables. only in the parent node

}

func replaceVariableWithReturnValues(c *Condition, returnValues *map[string][]interface{}) {
	listMap := make(map[string][]string, len(*returnValues))
	for k, v := range *returnValues {
		listMap[k] = []string{}
		for _, vv := range v {
			valueBytes, err := json.Marshal(vv)
			if err != nil {
				continue
			}
			valueString := removeQuotesAndBrackets(string(valueBytes))
			listMap[k] = append(listMap[k], valueString)
		}
	}
	stringsAndlists := PredefinedStringsAndLists{PredefinedListsWithoutRefs: listMap}
	listOfVariables := []string{}
	c.PrepareAndValidate(&listOfVariables, stringsAndlists)
}

func (c *Condition) Append(node Node) {
}

func (c *Condition) PrepareAndValidate(listOfVariables *[]string, stringsAndlists PredefinedStringsAndLists) (bool, error) {

	if strings.HasPrefix(c.Value, "#") {
		c.ValueContainsVariable = true
	}

	replacedFlag, err := ReplaceStringsAndListsInCondition(c, stringsAndlists)
	if err != nil {
		return false, err
	}
	valueFromVariableFlag := false
	if c.ValueContainsVariable && !replacedFlag {
		if slice.ContainsString(*listOfVariables, c.Value) {
			valueFromVariableFlag = true
		} else {
			return false, fmt.Errorf("could not replace variable in value [%+v]", c.Value)
		}
	} else {
		c.ValueContainsVariable = false // so we do it only once
	}
	if !valueFromVariableFlag {

		valid, err := ValidateOneCondition(c)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, fmt.Errorf("error in validating condition [%+v]", c)
		}

		err = ConvertConditionStringToIntFloatRegex(c)
		if err != nil {
			return false, err
		}

		if c.AttributeIsJsonpath {
			preparedJsonpath, err := prepareJsonpathQuery(c.AttributeJsonpathQuery)
			if err != nil {
				return false, err
			}
			c.PreparedJsonpathQuery = preparedJsonpath
		}
	}

	returnValuesInNode := false
	if len(c.ReturnValueJsonpath) > 0 {
		returnValuesInNode = true
		for k, _ := range c.ReturnValueJsonpath { // this is the list of variables currently available at this node:
			*listOfVariables = append(*listOfVariables, "#"+k)
		}
	}

	return returnValuesInNode, nil

}

func (c *Condition) ResetVariables() {
	c.Attribute = c.OriginalAttributeWithVariables
	c.Method = c.OriginalMethodWithVariables
	c.Value = c.OriginalValueWithVariables
	c.ValueContainsVariable = c.OriginalValueContainsVariable
}

// --------------------------------------
// parsing utilities
// --------------------------------------
func ParseConditionsTree(c interface{}) (Node, error) {

	conditionsTree, err := InterpretNode(c, "", false)
	if err != nil {
		return nil, err
	}

	return conditionsTree, nil
}

func InterpretNode(node interface{}, parentString string, isWithinAnyAll bool) (Node, error) {

	switch v := node.(type) {

	case map[string]interface{}:
		return handleMapStringInterface(v, parentString, isWithinAnyAll)

	case map[interface{}]interface{}:
		return handleMapInterfaceInterface(v, parentString, isWithinAnyAll)

	case []interface{}: // array of nodes
		if parentString == "" {
			if len(v) != 1 {
				return nil, fmt.Errorf("node type not supported. possible error: array of conditions without AND,OR (etc) parent")
				//return nil, fmt.Errorf("can't parse conditions %+v", v)
			}
			return InterpretNode(v[0], "", isWithinAnyAll) // recursion
		} else {
			return handleInterfaceArray(node, parentString, isWithinAnyAll)
		}

	default:
		return nil, fmt.Errorf("can't parse conditions %+v", v)
	}
	return nil, errors.New("can't parse conditions")
}

func handleMapInterfaceInterface(v map[interface{}]interface{}, parentString string, isWithinAnyAll bool) (Node, error) {

	v2 := mapInterfaceToMapString(v)
	return handleMapStringInterface(v2, parentString, isWithinAnyAll)

}

func handleMapStringInterface(v2 map[string]interface{}, parentString string, isWithinAnyAll bool) (Node, error) {

	// test if this is a condition:
	if isConditionNode(v2) {
		nodeOut, err := getNodeCondition(v2, parentString, isWithinAnyAll)
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
		notNode, err := getNotNode(v2, parentString, isWithinAnyAll)
		return notNode, err
	case "OR", "AND", "", "condition", "conditions", "conditionsTree":
		val, nodeType, err := getNodeValType(v2, parentString)
		if err != nil {
			return nil, err
		}
		node, err := InterpretNode(val, nodeType, isWithinAnyAll) // recursion!
		if err != nil {
			return nil, err
		}
		return node, nil
	default:
		return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
	}
	return nil, fmt.Errorf("can't interpret map[interface{}]interface{}")
}

func getNodeCondition(v map[string]interface{}, parentString string, isWithinAnyAll bool) (Node, error) {

	cond, err := ReadCondition(v, isWithinAnyAll)
	if err != nil {
		return nil, err
	}
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
			}
			anyAllNode.SetReturnValueJsonpath(returnValueJsonpathMap)

		default:
			node, err := InterpretNode(val, key, true) // recursion!
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

func getNotNode(v2 map[string]interface{}, parentString string, isWithinAnyAll bool) (Node, error) {
	err := isValidNotNode(v2)
	if err != nil {
		return nil, err
	}
	val, nodeType, err := getNodeValType(v2, parentString)
	if err != nil {
		return nil, err
	}
	notNode := &Not{}
	nodeInner, err := InterpretNode(val, nodeType, isWithinAnyAll) // recursion!
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

func handleInterfaceArray(node interface{}, parentString string, isWithinAnyAll bool) (Node, error) {
	v2 := node.([]interface{})
	nodes, err := getNodeByParentString(parentString)

	if err != nil {
		return nil, err
	}
	for _, subNode := range v2 {
		subNode2, err := InterpretNode(subNode, "", isWithinAnyAll) // recursion!
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
