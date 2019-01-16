package session

import (
	"errors"

	"github.com/coreos/go-iptables/iptables"
)

// ErrRuleNotFound is returned when you try to delete a rule that hasn't been created or
// has been already deleted.
var ErrRuleNotFound = errors.New("rule not found")

// Rule represents the the part of the iptables rule after the table name and chain name.
// For example, in "iptables -t nat -I PREROUTING -p tcp -j DROP", the Rule would be
// written like []string{"-p", "tcp", "-j" "DROP"}.
type Rule []string

// Session represents the state of a running netinject process. It takes care of creating
// the requested rules and cleaning them up when the program exits. It is not fit for
// concurrent access.
type Session struct {
	Protocol    iptables.Protocol
	Table       string
	InputChain  string
	OutputChain string
	ipt         iptables.IPTables
	inputRules  map[string]Rule
	outputRules map[string]Rule
}

// Validate ensures that the table, INPUT chain and OUTPUT chain exist for a given
// session.
func (s *Session) Validate() error {
	chains, err := s.ipt.ListChains(s.Table)
	if err != nil {
		return err
	}

	// Because Go has no nice way to do set inclusion without writing a whole bunch of
	// boiler plate, let's just stick this stuff into a map and then query it.
	includes := map[string]bool{}
	for _, chain := range chains {
		includes[chain] = true
	}
	_, ok := includes[s.InputChain]
	if !ok {
		return errors.New("INPUT chain not found in the filter table")
	}
	_, ok = includes[s.OutputChain]
	if !ok {
		return errors.New("OUTPUT chain not found in the filter table")
	}
	return nil
}

// Cleanup deletes the rules created, leaving the system like it was before.
func (s *Session) Cleanup() error {
	for _, rule := range s.inputRules {
		err := s.ipt.Delete(s.Table, s.InputChain, rule...)
		if err != nil {
			return err
		}
	}
	for _, rule := range s.outputRules {
		err := s.ipt.Delete(s.Table, s.OutputChain, rule...)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateInputRule appends an input rule to the session's table. It will be automatically
// deleted when the session is finished.
func (s *Session) CreateInputRule(name string, rule Rule) error {
	return s.createRule(name, rule, s.InputChain, s.inputRules)
}

// CreateOutputRule appends an output rule to the session's table. It will be
// automatically deleted when the session is finished.
func (s *Session) CreateOutputRule(name string, rule Rule) error {
	return s.createRule(name, rule, s.OutputChain, s.outputRules)
}

// DeleteInputRule deletes an already created input rule. An error is returned when you
// attempt to delete a rule which does not exist.
func (s *Session) DeleteInputRule(name string) error {
	return s.deleteRule(name, s.InputChain, s.inputRules)
}

// DeleteOutputRule deletes an already created output rule. An error is returned when you
// attempt to delete a rule which does not exist.
func (s *Session) DeleteOutputRule(name string) error {
	return s.deleteRule(name, s.OutputChain, s.outputRules)
}

func (s *Session) createRule(name string, rule Rule, chain string, rules map[string]Rule) error {
	err := s.ipt.Append(s.Table, chain, rule...)
	if err != nil {
		return err
	}
	rules[name] = rule
	return nil
}

func (s *Session) deleteRule(name string, chain string, rules map[string]Rule) error {
	rule, ok := rules[name]
	if !ok {
		return ErrRuleNotFound
	}
	err := s.ipt.Delete(s.Table, chain, rule...)
	if err != nil {
		return err
	}
	delete(rules, name)
	return nil
}
