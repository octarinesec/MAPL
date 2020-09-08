package MAPL_engine

import (
	"log"
)

type MessageCoverage struct {
	Covered                  bool     `json:"covered"`
	Decision                 int      `json:"decision"`
	IdsOfCoveringRules       []string `json:"idsOfCoveringRules"`
	DecisionsOfCoveringRules []int    `json:"decisionsOfCoveringRules"`
}

func Coverage(messages *Messages, rules *Rules) (messageCoverage map[string]MessageCoverage, ruleCoverage map[string][]string) {

	log.Println("testing Coverage")

	ruleCoverage = make(map[string][]string)

	emptyVec := []string{}
	for _, rule := range rules.Rules {
		//rc := RuleCoverage{rule.RuleID, false, emptyVec}
		//ruleCoverage = append(ruleCoverage, rc)
		ruleCoverage[rule.RuleID] = emptyVec
	}

	messageCoverage = make(map[string]MessageCoverage)

	for _, message := range messages.Messages {

		decision, _, _, decisions, appliedRulesIndices,_ ,_:= Check(&message, rules)
		appliedRulesIds := []string{}
		for i_rule := range appliedRulesIndices {
			rule_index := int(appliedRulesIndices[i_rule])
			appliedRulesIds = append(appliedRulesIds, rules.Rules[rule_index].RuleID)
			ruleCoverage[rules.Rules[rule_index].RuleID] = append(ruleCoverage[rules.Rules[rule_index].RuleID], message.MessageID)
		}


		_, nonDefaultDecisions := findNonDefaultDecisions(decisions)

		flag := false
		if decision != DEFAULT {
			flag = true
		}

		messageCoverage[message.MessageID] = MessageCoverage{flag, decision, appliedRulesIds, nonDefaultDecisions}
	}

	//fmt.Printf("%+v\n", messageCoverage)
	//fmt.Printf("%+v\n", ruleCoverage)
	return messageCoverage, ruleCoverage

}

func findNonDefaultDecisions(vec []int) (nonDefaultIndices, nonDefaultDecisions []int) {

	for i, v := range vec {
		if v != DEFAULT {
			nonDefaultIndices = append(nonDefaultIndices, i)
			nonDefaultDecisions = append(nonDefaultDecisions, v)
		}
	}
	return nonDefaultIndices, nonDefaultDecisions
}
