package waf

import "strings"

type acNode struct {
	next    map[byte]int
	fail    int
	outputs []string
}

type automaton struct{ nodes []acNode }

func newAutomaton(words []string) *automaton {
	a := &automaton{nodes: []acNode{{next: make(map[byte]int)}}}
	for _, word := range words {
		word = strings.ToLower(word)
		if word == "" {
			continue
		}
		state := 0
		for i := 0; i < len(word); i++ {
			b := word[i]
			next, ok := a.nodes[state].next[b]
			if !ok {
				next = len(a.nodes)
				a.nodes[state].next[b] = next
				a.nodes = append(a.nodes, acNode{next: make(map[byte]int)})
			}
			state = next
		}
		a.nodes[state].outputs = append(a.nodes[state].outputs, word)
	}
	queue := make([]int, 0, len(a.nodes))
	for _, child := range a.nodes[0].next {
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for b, child := range a.nodes[state].next {
			queue = append(queue, child)
			fallback := a.nodes[state].fail
			for fallback != 0 {
				if _, ok := a.nodes[fallback].next[b]; ok {
					break
				}
				fallback = a.nodes[fallback].fail
			}
			if next, ok := a.nodes[fallback].next[b]; ok && next != child {
				a.nodes[child].fail = next
			}
			a.nodes[child].outputs = append(a.nodes[child].outputs, a.nodes[a.nodes[child].fail].outputs...)
		}
	}
	return a
}

func (a *automaton) scan(text string, found map[string]struct{}) {
	if a == nil {
		return
	}
	state := 0
	for i := 0; i < len(text); i++ {
		b := text[i]
		for state != 0 {
			if _, ok := a.nodes[state].next[b]; ok {
				break
			}
			state = a.nodes[state].fail
		}
		if next, ok := a.nodes[state].next[b]; ok {
			state = next
		}
		for _, word := range a.nodes[state].outputs {
			found[word] = struct{}{}
		}
	}
}
