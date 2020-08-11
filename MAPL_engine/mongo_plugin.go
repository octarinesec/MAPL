package MAPL_engine

import (
	"fmt"
	"github.com/globalsign/mgo/bson"
	"strconv"
	"strings"
)

func (a *And) ToMongoQuery() (bson.M, error) {
	return bson.M{}, fmt.Errorf("AND not supported yet")
}

func (o *Or) ToMongoQuery() (bson.M, error) {
	return bson.M{}, fmt.Errorf("OR not supported yet")
}

func (n *Not) ToMongoQuery() (bson.M, error) {
	return bson.M{}, fmt.Errorf("NOT not supported yet")
}

func (a *Any) ToMongoQuery() (bson.M, error) {
	return bson.M{}, fmt.Errorf("ANY not supported yet")
}

func (a *All) ToMongoQuery() (bson.M, error) {
	return bson.M{}, fmt.Errorf("ALL not supported yet")
}

func (c *Condition) ToMongoQuery() (bson.M, error) {

	//see: https://docs.mongodb.com/manual/reference/operator/query/

	if c.Attribute != "jsonpath" {
		return bson.M{}, fmt.Errorf("attribute is not a jsonpath")
	}

	field := strings.Replace(c.OriginalAttribute, "jsonpath:$.", "raw.", 1)

	field, err := removeQuotes(field)
	if err != nil {
		return bson.M{}, err
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
	case "IN", "NIN":
		return bson.M{}, fmt.Errorf("methods IN,NIN are not supported yet")
	}

	return q, nil
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
