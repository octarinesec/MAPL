package MAPL_engine

import (
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"strconv"
	"strings"
)

func (a *And) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) { //parentString is irrelevant here

	q_array := []bson.M{}
	pipeline := []bson.M{}

	for _, node := range a.Nodes {
		q, pipelineAppend, err := node.ToMongoQuery(base, "", inArrayCounter)
		if err != nil {
			return bson.M{}, []bson.M{}, err
		}
		q_array = append(q_array, q)
		for _, p := range pipelineAppend {
			pipeline = append(pipeline, p)
		}
	}

	q_and := bson.M{"$and": q_array}

	return q_and, pipeline, nil
}

func (o *Or) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) { //parentString is irrelevant here

	q_array := []bson.M{}
	pipeline := []bson.M{}
	for _, node := range o.Nodes {
		q, pipelineAppend, err := node.ToMongoQuery(base, "", inArrayCounter)
		if err != nil {
			return bson.M{}, []bson.M{}, err
		}
		q_array = append(q_array, q)
		for _, p := range pipelineAppend {
			pipeline = append(pipeline, p)
		}
	}

	q_or := bson.M{"$or": q_array}

	return q_or, pipeline, nil
}

func (n *Not) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) { //parentString is irrelevant here

	q, pipeline, err := n.Node.ToMongoQuery(base, "", inArrayCounter)
	if err != nil {
		return bson.M{}, []bson.M{}, err
	}

	q_not := bson.M{"$nor": []bson.M{q}} // to avoid "unknown top level operator: $not" we use $nor with a single condition

	return q_not, pipeline, nil
}

func (a *All) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) { //parentString is irrelevant here
	if strings.HasSuffix(a.ParentJsonpathAttributeOriginal, "[:]") || strings.HasSuffix(a.ParentJsonpathAttributeOriginal, "[*]") {
		inArrayCounter += 1
	}
	if strings.HasPrefix(a.ParentJsonpathAttributeOriginal, "jsonpath:$..") {
		return bson.M{}, []bson.M{}, fmt.Errorf("deepscan is not supported")
	}
	parentField := strings.Replace(a.ParentJsonpathAttributeOriginal, "jsonpath:$.", base+".", 1)
	parentField = strings.Replace(parentField, "jsonpath:$RELATIVE.", "", 1)
	parentField = strings.Replace(parentField, "[:]", "", -1)
	parentField = strings.Replace(parentField, "[*]", "", -1)

	q, pipeline, err := a.Node.ToMongoQuery(base, "", inArrayCounter+1)
	if err != nil {
		return bson.M{}, []bson.M{}, err
	}
	if len(pipeline) != 0 {
		return bson.M{}, []bson.M{}, fmt.Errorf("KEY/VALUE in ALL node is not supported")
	}

	q_not := bson.M{"$nor": []bson.M{q}}
	q_all_not := bson.M{parentField: bson.M{"$elemMatch": q_not}}
	q_not_all_not := bson.M{"$nor": []bson.M{q_all_not}} // all == not(any(not(conditions))

	return q_not_all_not, pipeline, nil

}

func (a *Any) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) { //parentString is irrelevant here

	if strings.HasSuffix(a.ParentJsonpathAttributeOriginal, "[:]") || strings.HasSuffix(a.ParentJsonpathAttributeOriginal, "[*]") {
		inArrayCounter += 1
	}

	if strings.HasPrefix(a.ParentJsonpathAttributeOriginal, "jsonpath:$..") {
		return bson.M{}, []bson.M{}, fmt.Errorf("deepscan is not supported")
	}
	parentField := strings.Replace(a.ParentJsonpathAttributeOriginal, "jsonpath:$.", base+".", 1)
	parentField = strings.Replace(parentField, "jsonpath:$RELATIVE.", "", 1)
	parentField = strings.Replace(parentField, "[:]", "", -1)
	parentField = strings.Replace(parentField, "[*]", "", -1)

	q, pipeline, err := a.Node.ToMongoQuery(base, parentField, inArrayCounter+1)
	if err != nil {
		return bson.M{}, []bson.M{}, err
	}

	var q_all bson.M
	if len(pipeline) == 0 {
		q_all = bson.M{parentField: bson.M{"$elemMatch": q}}
	} else {
		q_all = q
	}
	return q_all, pipeline, nil
}

func (c *Condition) ToMongoQuery(base string, parentString string, inArrayCounter int) (bson.M, []bson.M, error) {

	//see: https://docs.mongodb.com/manual/reference/operator/query/

	initialSteps := []bson.M{}

	if c.Attribute != "jsonpath" {
		return bson.M{}, []bson.M{}, fmt.Errorf("attribute is not a jsonpath")
	}

	var field string
	if strings.HasPrefix(c.OriginalAttribute, "jsonpath:$RELATIVE") {
		field = strings.Replace(c.OriginalAttribute, "jsonpath:$RELATIVE.", "", 1)
	}

	if strings.HasPrefix(c.OriginalAttribute, "jsonpath:$VALUE") {

		if inArrayCounter >= 2 {
			return bson.M{}, []bson.M{}, fmt.Errorf("VALUE within array is not supported") // if neccessary we can do [$unwind, $addFields, $merge] steps!
		}
		//if strings.Contains(c.OriginalAttribute,"jsonpath:$VALUE."){
		//	return bson.M{}, []bson.M{}, fmt.Errorf("json VALUE is not supported")
		//}
		subField := strings.Replace(c.OriginalAttribute, "jsonpath:$VALUE", "", 1)
		addedField := fmt.Sprintf("addedField.%v", parentString)
		field = fmt.Sprintf("%v.v%v", addedField, subField)

		addFieldStep := bson.M{"$addFields": bson.M{addedField: bson.M{"$objectToArray": "$" + parentString}}}

		initialSteps = append(initialSteps, addFieldStep)
	}

	if strings.HasPrefix(c.OriginalAttribute, "jsonpath:$KEY") {

		if inArrayCounter >= 2 {
			return bson.M{}, []bson.M{}, fmt.Errorf("KEY within array is not supported")
		}
		if strings.Contains(c.OriginalAttribute, "jsonpath:$KEY.") {
			return bson.M{}, []bson.M{}, fmt.Errorf("json KEY is not supported")
		}

		field0 := parentString
		field1 := fmt.Sprintf("addedField.%v", field0)
		field = fmt.Sprintf("%v.k", field1)

		addFieldStep := bson.M{"$addFields": bson.M{field1: bson.M{"$objectToArray": "$" + field0}}}

		initialSteps = append(initialSteps, addFieldStep)
	}

	if strings.HasPrefix(c.OriginalAttribute, "jsonpath:$.") {

		newBase := ""
		if len(base) > 0 {
			newBase = base + "."
		}
		field = strings.Replace(c.OriginalAttribute, "jsonpath:$.", newBase, 1)
	}

	field, err := removeQuotes(field)
	if err != nil {
		return bson.M{}, []bson.M{}, err
	}

	isNumberFlag, num := isNumber(c.Value)
	var valToUse interface{}
	if isNumberFlag {
		valToUse = num
	} else {
		valToUse = c.Value
	}

	q := bson.M{}

	switch strings.ToUpper(c.Method) {
	case "EQ":
		q = bson.M{field: bson.M{"$eq": valToUse}}
	case "NEQ", "NE":
		q = bson.M{field: bson.M{"$ne": valToUse}}
	case "GT":
		q = bson.M{field: bson.M{"$gt": valToUse}}
	case "GE":
		q = bson.M{field: bson.M{"$gte": valToUse}}
	case "LT":
		q = bson.M{field: bson.M{"$lt": valToUse}}
	case "LE":
		q = bson.M{field: bson.M{"$lte": valToUse}}
	case "EX":
		q = bson.M{field: bson.M{"$exists": true}}
	case "NEX":
		q = bson.M{field: bson.M{"$exists": false}}
	case "RE":
		q = bson.M{field: bson.M{"$regex": c.Value}}
	case "NRE":
		q1 := bson.M{field: bson.M{"$not": bson.M{"$regex": c.Value}}}
		q2 := bson.M{field: bson.M{"$exists": true}}
		q = bson.M{"$and": []bson.M{q1, q2}}
		// db.raw_data.find({"$and":[{"raw.metadata.labels.foo":{"$not":{"$regex":"ar2"}}},{"raw.metadata.labels.foo":{"$exists":true}}]})
	case "IN", "NIN": // it is not supported natively. we convert it to RE/NRE first which are supported.
		return bson.M{}, []bson.M{}, fmt.Errorf("methods IN,NIN are not supported yet")
	}

	return q, initialSteps, nil
}

func isNumber(str string) (bool, float64) {
	if s, err := strconv.ParseFloat(str, 64); err == nil {
		return true, s
	}
	return false, -1.0
}

func removeQuotes(str string) (string, error) {
	// we first check that the quotes make sense (just counting. we can test that they are correctly aligned but we won't).
	numQuote1 := strings.Count(str, `"`)
	numQuote2 := strings.Count(str, `'`)
	numLeftBrackets := strings.Count(str, `[`)
	numRightBrackets := strings.Count(str, `]`)

	if numQuote1%2 != 0 || numQuote2%2 != 0 {
		return "", fmt.Errorf("misalligned quotes")
	}

	if numLeftBrackets != numRightBrackets {
		return "", fmt.Errorf("misalligned square brackets")
	}
	str = strings.Replace(str, `"`, "", -1)
	str = strings.Replace(str, `'`, "", -1)
	str = strings.Replace(str, `[`, ".", -1) // add a dot if it is missing
	str = strings.Replace(str, `]`, "", -1)

	numDoubleDots := strings.Count(str, `..`)
	for i := 0; i < numDoubleDots; i++ {
		str = strings.Replace(str, "..", ".", -1)
		numDoubleDotsTemp := strings.Count(str, `..`)
		if numDoubleDotsTemp == 0 {
			break
		}
	}

	return str, nil
}
