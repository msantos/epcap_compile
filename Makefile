.PHONY: all compile clean test examples eg dialyzer typer

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

typer:
	@typer -pa _build/default/lib/epcap_compile/ebin \
		   -I include \
		   --plt _build/default/*_plt \
		   -r ./src
