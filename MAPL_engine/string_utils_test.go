package MAPL_engine

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestRemoveDotQuotes(t *testing.T) {
	Convey("TestRemoveDotQuotes", t, func() {

		strIn:="$.metadata.labels.foo"
		strOut:=RemoveDotQuotes(strIn)
		expectedStrOut:="$.metadata.labels.foo"
		So(strOut,ShouldEqual,expectedStrOut)

		strIn="$.metadata.labels.'foo'"
		strOut=RemoveDotQuotes(strIn)
		expectedStrOut="$.metadata.labels.foo"
		So(strOut,ShouldEqual,expectedStrOut)

		strIn=`$.metadata.labels."foo"`
		strOut=RemoveDotQuotes(strIn)
		expectedStrOut="$.metadata.labels.foo"
		So(strOut,ShouldEqual,expectedStrOut)

		strIn=`$.metadata.labels.["foo"]`
		strOut=RemoveDotQuotes(strIn)
		expectedStrOut=`$.metadata.labels.["foo"]`
		So(strOut,ShouldEqual,expectedStrOut)

	})
}
