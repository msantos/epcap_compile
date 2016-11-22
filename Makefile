.PHONY: all compile clean test examples eg dialyzer

REBAR ?= rebar3

all: compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

test:
	@$(REBAR) ct

examples: eg
eg:
	@erlc -I deps -o ebin examples/*.erl

dialyzer:
	@$(REBAR) dialyzer
