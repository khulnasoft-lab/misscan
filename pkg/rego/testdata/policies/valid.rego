# METADATA
# schemas:
# - input: schema["input"]
package misscan.test_valid

deny {
	input.Stages[0].Commands[0].Cmd == "lol"
}
