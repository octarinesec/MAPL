package MAPL_engine

type PredefinedStringsAndLists struct {
	PredefinedStrings map[string]string `yaml:"predefinedStrings,omitempty" json:"predefinedStrings,omitempty" bson:"PredefinedStrings" structs:"PredefinedStrings,omitempty"`
	PredefinedLists map[string][]string `yaml:"predefinedLists,omitempty" json:"predefinedLists,omitempty" bson:"PredefinedLists" structs:"PredefinedLists,omitempty"`
}
