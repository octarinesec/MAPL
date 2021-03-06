package MAPL_engine

import "go.mongodb.org/mongo-driver/bson"

type QueryType string

const (
	QueryTypeSimple    QueryType = "simple"
	QueryTypeAggregate QueryType = "aggregate"
)

type MaplToMongoResult struct {
	Type  QueryType
	Query interface{}
}

func (rule *Rule) ToMongoQuery(parentField string) (MaplToMongoResult, error) {

	if !rule.ruleAlreadyPrepared {
		rule.SetPredefinedStringsAndLists(GlobalPredefinedStringsAndLists) // use the global if not set already
	}

	if rule.preparedRule.Conditions.ConditionsTree == nil {
		return MaplToMongoResult{QueryTypeSimple, bson.M{}}, nil
	}

	query, added_pipeline, err := rule.preparedRule.Conditions.ConditionsTree.ToMongoQuery(parentField, "", 0)
	if err != nil {

		return MaplToMongoResult{"", nil}, err

	}

	if len(added_pipeline) == 0 {
		return MaplToMongoResult{QueryTypeSimple, query}, nil
	}
	query_pipeline := append(added_pipeline, bson.M{"$match": query})
	return MaplToMongoResult{QueryTypeAggregate, query_pipeline}, nil

}
