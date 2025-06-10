# METADATA
# schemas:
# - input: schema["input"]
package misscan.test

deny {
	input.Stages[0].Commands[0].FooBarNothingBurger == "lol"
}
