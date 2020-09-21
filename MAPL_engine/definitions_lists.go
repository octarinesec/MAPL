package MAPL_engine

type PredefinedStringsAndLists struct {
	PredefinedStrings map[string]string `yaml:"predefinedStrings,omitempty" json:"predefinedStrings,omitempty" bson:"predefinedStrings" structs:"predefinedStrings,omitempty"`
	PredefinedLists map[string][]string `yaml:"predefinedLists,omitempty" json:"predefinedLists,omitempty" bson:"predefinedLists" structs:"predefinedLists,omitempty"`
	PredefinedListsWithoutRefs map[string][]string `yaml:"-,omitempty" json:"-,omitempty" bson:"predefinedListsWithoutRefs" structs:"predefinedListsWithoutRefs,omitempty"`
}
