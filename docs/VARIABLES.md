# Variables

Returned values may be used in a one-attribute-condition value field to create complex rules (i.e. we pass variables from one condition to another).


### Example

We have a json with an array of alerts.

An alert contains the command field and a filename field.

We test if a new command (alert type NewCommand) was run that is a result of another command creating it.

In the first part of the following rule we collect a list of the new commands that were run (in the newCommand returnedValue)

in the second part check alerts of type NewFile and check if the filename is in the list of the new commands.



    conditions:

      AND:

        - ANY:
            parentJsonpathAttribute: "jsonpath:$.alerts[:]"
            returnValueJsonpath:
              newCommand: jsonpath:$RELATIVE.command
            condition:
              attribute: jsonpath:$RELATIVE.alertSubtype
              method: EQ
              value: "NewCommand

        - ANY:
            parentJsonpathAttribute: "jsonpath:$.alerts[:]"

            condition:
              AND:
              - attribute: jsonpath:$RELATIVE.alertSubtype
                method: EQ
                value: "NewFile"
              - attribute: jsonpath:$RELATIVE.filename
                method: IN
                value: "#newCommand"

