package extras

import (
	"fmt"
	"github.com/octarinesec/MAPL/MAPL_engine"
	"os"
	"strings"
)

// Package extras contains conversion of rules:
// - rules that are written with conditions on labels are converted to be using only the service names
//

const NoComplyingSender = "NO_SENDER_COMPLYING_WITH_RULE"
const NoComplyingReceiver = "NO_RECEIVER_COMPLYING_WITH_RULE"

// this is an empty message populated later with message.SenderLabels and message.DestinationLabels to test the rule conditions on the message.
var message_attributes MAPL_engine.MessageAttributes

// function RemoveLabelConditionsFromRule is the main function for translation of conditions on Sender and Receiver Labels to
// the equivalent Sender/Receiver names
func RemoveLabelConditionsFromRule(rule MAPL_engine.Rule, service_labels map[string]map[string]string, service_labels_explicit map[string]map[string]string) (new_rules MAPL_engine.Rules,err error) {

	translateSenderLabelsFlag := 0
	translateReceiverLabelsFlag := 0

	senders := []string{}
	receivers := []string{}
	receivers_map := map[string][]string{}

	rule_temp := rule // we work on rule_temp. since we send a pointer to rule_temp and changes are made to it.
	new_rule := rule  // by default we just copy the rule without a change
	// check for label conditions:
	for _, andCondition := range (rule_temp.DNFConditions) {
		for _, condition := range (andCondition.ANDConditions) {
			if condition.AttributeIsSenderLabel {
				//sanity: if we translate sender labels to sender names then the sender name must be "*"
				if (rule_temp.Sender.SenderName != "*" && rule_temp.Sender.SenderName != "*:*") || (rule_temp.Sender.SenderType != "workload" && rule_temp.Sender.SenderType != "*") {
					return MAPL_engine.Rules{}, fmt.Errorf("when translating rules: sender!=\"*\"")
				}
				translateSenderLabelsFlag++
			}
			if condition.AttributeIsReceiverLabel {
				//sanity: if we translate receiver labels to receiver names then the receiver name must be "*"
				if (rule_temp.Receiver.ReceiverName != "*" && rule_temp.Receiver.ReceiverName != "*:*") || (rule_temp.Receiver.ReceiverType != "workload" && rule_temp.Receiver.ReceiverType != "*") {
					return MAPL_engine.Rules{}, fmt.Errorf("when translating rules: receiver!=\"*\"")
				}
				translateReceiverLabelsFlag++
			}
			if condition.ValueIsReceiverLabel {
				return MAPL_engine.Rules{}, fmt.Errorf("when translating rules: labels as values are not supported")
			}
		}
	}

	if translateSenderLabelsFlag > 0 && translateReceiverLabelsFlag > 0 { // this is a special case: there are conditions both on the sender labels and the receiver labels
		rule_temp = rule
		if translateSenderLabelsFlag == 1 {
			senders = getServicesFromRule(&rule_temp, service_labels, 1) // test which senders with wildcards satisfy at all the conditions
		} else {
			senders = getServicesFromRule(&rule_temp, service_labels_explicit, 1) // test which senders without wildcards satisfy at all the conditions (explicit list)
		}
		if len(senders) == 0 {
			senders = []string{NoComplyingSender}
		}
		rule_temp = rule
		if translateReceiverLabelsFlag == 1 {
			receivers = getServicesFromRule(&rule_temp, service_labels, 2) // test which receivers with wildcards satisfy one receiver label condition
		} else {
			receivers = getServicesFromRule(&rule_temp, service_labels_explicit, 2)
		}
		if len(receivers) == 0 {
			receivers = []string{NoComplyingReceiver}
		}
		rule_temp = rule
		service_labels_sender := service_labels
		if translateSenderLabelsFlag > 1 {
			service_labels_sender = service_labels_explicit
		}
		service_labels_receiver := service_labels
		if translateReceiverLabelsFlag > 1 {
			service_labels_receiver = service_labels_explicit
		}
		receivers_map = getServicesFromRuleWithSenderReceiverLists(&rule_temp, service_labels_sender, service_labels_receiver, senders, receivers) // now go over all the pairs and test which are satisfied together

		if len(receivers_map) == 0 {
			return new_rules, nil
		}

		useRulePerReceiverFlag := false // test if all the receivers are satisfied by the same sender list:
		i := 0
		var value0 []string
		for _, value := range (receivers_map) {
			if i == 0 {
				value0 = value
			} else {
				if !testSliceEquality(value, value0) {
					useRulePerReceiverFlag = true
				}
			}
			i++
		}

		if !useRulePerReceiverFlag { // all the receivers are satisfied by the same sender list. then we can make it one rule
			//sanity:
			if !testSliceEquality(senders, value0) {
				return MAPL_engine.Rules{}, fmt.Errorf("somethings is wrong: in \"translateSenderLabelsFlag && translateReceiverLabelsFlag == true\" part")
			}
			new_rule.DNFConditions = removeLabelConditions(&new_rule)
			new_rule.Sender.SenderName = strings.Join(senders, ",")
			new_rule.Sender.SenderType = "workload"
			new_rule.Receiver.ReceiverName = strings.Join(receivers, ",")
			new_rule.Receiver.ReceiverType = "workload"
			new_rules.Rules = append(new_rules.Rules, new_rule)
		} else { // NOT all the receivers are satisfied by the same sender list. then we have to make one rule per receiver in the list
			counter := 0
			for r, s := range (receivers_map) {
				counter += 1
				new_rule = rule
				new_rule.RuleID = fmt.Sprintf("%s-%d", new_rule.RuleID, counter)
				new_rule.DNFConditions = removeLabelConditions(&new_rule)
				new_rule.Sender.SenderName = strings.Join(s, ",")
				new_rule.Sender.SenderType = "workload"
				new_rule.Receiver.ReceiverName = r
				new_rule.Receiver.ReceiverType = "workload"
				new_rules.Rules = append(new_rules.Rules, new_rule)
			}
		}
	} else {
		if translateSenderLabelsFlag > 0 { // there are only conditions on the sender labels
			if translateSenderLabelsFlag == 1 {
				senders = getServicesFromRule(&rule_temp, service_labels, 1) // test which senders with wildcards satisfy at all the conditions
			} else {
				senders = getServicesFromRule(&rule_temp, service_labels_explicit, 1) // test which senders without wildcards satisfy at all the conditions (explicit list)
			}
			if len(senders) == 0 {
				senders = []string{NoComplyingSender}
			}
			new_rule.DNFConditions = removeLabelConditions(&new_rule)
			new_rule.Sender.SenderName = strings.Join(senders, ",")
			new_rule.Sender.SenderType = "workload"
			new_rules.Rules = append(new_rules.Rules, new_rule)
		}
		if translateReceiverLabelsFlag > 0 { // there are only conditions on the receiver labels
			if translateReceiverLabelsFlag == 1 {
				receivers = getServicesFromRule(&rule_temp, service_labels, 2) // test which receivers with wildcards satisfy one receiver label condition
			} else {
				receivers = getServicesFromRule(&rule_temp, service_labels_explicit, 2)
			}
			if len(receivers) == 0 {
				receivers = []string{NoComplyingReceiver}
			}
			new_rule.DNFConditions = removeLabelConditions(&new_rule)
			new_rule.Receiver.ReceiverName = strings.Join(receivers, ",")
			new_rule.Receiver.ReceiverType = "workload"
			new_rules.Rules = append(new_rules.Rules, new_rule)
		}
		if translateSenderLabelsFlag == 0 && translateReceiverLabelsFlag == 0 { // there are no condtions on any labels, so we just copy the rule
			new_rules.Rules = append(new_rules.Rules, new_rule)
		}
	}
	return new_rules, nil
}

// function RemoveLabelConditionsFromRules calls RemoveLabelConditionsFromRule which is the main function for translation of conditions on Sender and Receiver Labels to
// the equivalent Sender/Receiver names
func RemoveLabelConditionsFromRules(rules *MAPL_engine.Rules, service_labels, service_labels_explicit map[string]map[string]string) (newRules MAPL_engine.Rules) {

	newRules=RemoveLabelConditionsFromRulesInner(rules,service_labels, service_labels_explicit)
	// recreate regular expressions and convert condition values:
	MAPL_engine.ConvertFieldsToRegexManyRules(&newRules)
	MAPL_engine.ConvertConditionStringToIntFloatRegexManyRules(&newRules)

	return newRules
}

func RemoveLabelConditionsFromRulesInner(rules *MAPL_engine.Rules, service_labels, service_labels_explicit map[string]map[string]string) (newRules MAPL_engine.Rules) {

	MAPL_engine.ConvertConditionStringToIntFloatRegexManyRules(rules)

	for _, rule := range (rules.Rules) { // go over all of the rules

		new_rules := RemoveLabelConditionsFromRule(rule, service_labels, service_labels_explicit)
		for _, new_rule := range (new_rules.Rules) {
			new_rule.AlreadyConvertedFieldsToRegexFlag = false
			newRules.Rules = append(newRules.Rules, new_rule)
		}
	}

	return newRules
}



// getSendersFromRule translate the conditions on the labels into services that satisfy them
func getServicesFromRule(rule *MAPL_engine.Rule, service_labels map[string]map[string]string, sender_receiver int) (services_list []string) {

	//result:=false
	for name, labels := range (service_labels) {
		message := message_attributes

		if sender_receiver == 1 {
			message.SourceLabels = labels
			message.DestinationLabels = nil
		} else {
			message.DestinationLabels = labels
			message.SourceLabels = nil
		}

		rule.DNFConditions = filterLabelRules(rule.DNFConditions, sender_receiver)
		result := MAPL_engine.TestConditions(rule, &message) //&& result

		if result {
			services_list = append(services_list, name)
		}
	}
	return services_list
}

// filterLabelRules: a helper function that removes irrelevant conditions from the rule
func filterLabelRules(dnfConditions []MAPL_engine.ANDConditions, sender_receiver int) (dnfCondtions_out []MAPL_engine.ANDConditions) {

	for _, andCondition := range (dnfConditions) {
		andCondition_temp := MAPL_engine.ANDConditions{}
		for _, condition := range (andCondition.ANDConditions) {

			if sender_receiver == 1 {
				if !condition.AttributeIsSenderLabel {
					condition.Attribute = "true" // ignore non-relevant conditions
				}
			}

			if sender_receiver == 2 {
				if !condition.AttributeIsReceiverLabel {
					condition.Attribute = "true" // ignore non-relevant conditions
				}
			}

			if sender_receiver == 3 {
				if !condition.AttributeIsSenderLabel && !condition.AttributeIsReceiverLabel {
					condition.Attribute = "true" // ignore non-relevant conditions
				}
			}

			andCondition_temp.ANDConditions = append(andCondition_temp.ANDConditions, condition)
		}
		dnfCondtions_out = append(dnfCondtions_out, andCondition_temp)
	}

	return dnfCondtions_out
}

// getServicesFromRuleWithSenderReceiverLists tests the label conditions for all the sender-receiver pairs (given as input)
func getServicesFromRuleWithSenderReceiverLists(rule *MAPL_engine.Rule, service_labels_senders, service_labels_receivers map[string]map[string]string, senders []string, receivers []string) (services_map map[string][]string) {

	services_map = make(map[string][]string)
	for _, r := range (receivers) {
		for _, s := range (senders) {

			if r == s { // we do not allow rule with sender == receiver
				continue
			}

			message := message_attributes
			message.SourceLabels = service_labels_senders[s]
			message.DestinationLabels = service_labels_receivers[r]
			// fix rule:
			rule.DNFConditions = filterLabelRules(rule.DNFConditions, 3)
			result := MAPL_engine.TestConditions(rule, &message)
			if result {
				services_map[r] = append(services_map[r], s) // all the senders per receiver
			}
		}
	}
	return services_map
}

// removeLabelConditions: remove conditions with sender/receiver labels. used after we translated the conditions into sender/receiver names
func removeLabelConditions(rule *MAPL_engine.Rule) (new_DNFConditions []MAPL_engine.ANDConditions) {
	for _, andCondition := range (rule.DNFConditions) {
		var temp_andConditions MAPL_engine.ANDConditions
		for _, condition := range (andCondition.ANDConditions) {
			if condition.AttributeIsSenderLabel || condition.AttributeIsReceiverLabel {
				//skip
			} else {
				temp_andConditions.ANDConditions = append(temp_andConditions.ANDConditions, condition)
			}
		}
		if len(temp_andConditions.ANDConditions) > 0 {
			new_DNFConditions = append(new_DNFConditions, temp_andConditions) // append only if there are still conditions after the removal of the label conditions
		}
	}
	return new_DNFConditions
}

// OutputRulesToFile: create a new yaml file of the new translated rules
func OutputRulesToFile(rules *MAPL_engine.Rules, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("can't create file")
	}
	defer f.Close()

	f.WriteString("rules:\n")
	for _, rule := range (rules.Rules) {
		fmt.Fprintf(f, "\n  - rule_id: %v\n", rule.RuleID)
		fmt.Fprintf(f, "    sender: \"%+v\"\n", rule.Sender)
		fmt.Fprintf(f, "    receiver: \"%+v\"\n", rule.Receiver)
		fmt.Fprintf(f, "    protocol: %v\n", rule.Protocol)
		fmt.Fprintf(f, "    resource:\n")
		fmt.Fprintf(f, "      resourceType: %v\n", rule.Resource.ResourceType)
		fmt.Fprintf(f, "      resourceName: \"%v\"\n", rule.Resource.ResourceName)
		fmt.Fprintf(f, "    operation: %v\n", rule.Operation)
		if len(rule.DNFConditions) > 0 {
			fmt.Fprintf(f, "    DNFconditions:\n")
			for _, and_conditions := range (rule.DNFConditions) {
				fmt.Fprintf(f, "      - ANDConditions:\n")
				for _, condition := range (and_conditions.ANDConditions) {
					fmt.Fprintf(f, "        - attribute: \"%v\"\n", condition.Attribute)
					fmt.Fprintf(f, "          method: %v\n", condition.Method)
					fmt.Fprintf(f, "          value: \"%v\"\n", condition.Value)
				}
			}
		}
		fmt.Fprintf(f, "    decision: %v\n", rule.Decision)
	}
	return nil
}

// printDNFConditions: prints the conditions to the console (used for debugging)
func printDNFConditions(dnfConditions []MAPL_engine.ANDConditions) {
	for _, andCondition := range (dnfConditions) {
		fmt.Println("- ANDCondions:")
		for _, condition := range (andCondition.ANDConditions) {
			fmt.Printf("  - Attribute: %v\n", condition.Attribute)
			fmt.Printf("    Method: %v\n", condition.Method)
			fmt.Printf("    Value: %v\n", condition.Value)
		}
	}
}

// testSliceEquality: compares two slices of strings
func testSliceEquality(a, b []string) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false;
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
