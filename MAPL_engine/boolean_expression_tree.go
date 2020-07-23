package MAPL_engine

import "fmt"
//--------------------------------------
type Node interface {
	Eval(message *MessageAttributes) bool
	Append(node Node)
	String2() string
}
//--------------------------------------
type And struct {
	nodes []Node
}

func (a *And) Eval(message *MessageAttributes) bool {
	x := true
	for _, node := range a.nodes {
		x = x && node.Eval(message)
	}
	return x
}
func (a *And) Append(node Node) {
	a.nodes = append(a.nodes, node)
}

func (a *And) String2() string {
	str := "("
	for i_node, node := range a.nodes {
		if i_node < len(a.nodes)-1 {
			str += node.String2() + " && "
		} else {
			str += node.String2()
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
	x := false
	for _, node := range o.nodes {
		x = x || node.Eval(message)
	}
	return x
}
func (o *Or) Append(node Node) {
	o.nodes = append(o.nodes, node)
}
func (o *Or) String2() string {
	str := "("
	for i_node, node := range o.nodes {
		if i_node < len(o.nodes)-1 {
			str += node.String2() + " || "
		} else {
			str += node.String2()
		}
	}
	str += ")"
	return str
}
//--------------------------------------
type True struct{}

func (t True) Eval(message *MessageAttributes) bool {
	return true
}
func (t True) Append(node Node) {
}
func (t True) String2() string {
	return "true"
}
//--------------------------------------
type False struct{}

func (f False) Eval(message *MessageAttributes) bool {
	return false
}
func (f False) Append(node Node) {
}
func (t False) String2() string {
	return "false"
}
//--------------------------------------
func (c Condition) Eval(message *MessageAttributes) bool {
	return testOneCondition(&c, message)
}
func (c Condition) Append(node Node) {
}
func (c Condition) String2() string {
	//return c.String()
	return fmt.Sprintf("<%v-%v-%v>", c.OriginalAttribute, c.Method, c.Value)
}
