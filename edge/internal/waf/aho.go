package waf

import "strings"

const maxRegexWindowBytes = 512
const regexWindowRadius = 256
const maxRegexWindowsPerRequest = 128

type scanWindow struct{ start, end int }

type acNode struct {
	next    map[byte]int
	fail    int
	outputs []string
}

type automaton struct{ nodes []acNode }

func newAutomaton(words []string) *automaton {
	a := &automaton{nodes: []acNode{{next: make(map[byte]int)}}}
	seen := make(map[string]struct{}, len(words))
	for _, word := range words {
		word = strings.ToLower(word)
		if word == "" {
			continue
		}
		if _, exists := seen[word]; exists {
			continue
		}
		seen[word] = struct{}{}
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

func (a *automaton) windows(text string, expired func() bool) ([]scanWindow, bool) {
	if a == nil {
		return nil, false
	}
	var out []scanWindow
	pending := scanWindow{}
	hasPending := false
	flush := func() {
		if hasPending && pending.end > pending.start {
			out = append(out, pending)
		}
		hasPending = false
	}
	state := 0
	for i := 0; i < len(text); i++ {
		if i&255 == 0 && expired != nil && expired() {
			return out, false
		}
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
		matchStart := len(text)
		for _, word := range a.nodes[state].outputs {
			if isShortAlphaNumericWord(word) && !keywordAtWordBoundary(text, i-len(word)+1, i+1) {
				continue
			}
			start := i - len(word) + 1 - regexWindowRadius
			if start < 0 {
				start = 0
			}
			matchStart = min(matchStart, start)
		}
		if matchStart < len(text) {
			end := min(i+1+regexWindowRadius, len(text))
			if !hasPending {
				pending = scanWindow{matchStart, end}
				hasPending = true
			} else {
				mergedStart := min(matchStart, pending.start)
				mergedEnd := max(end, pending.end)
				if matchStart <= pending.end {
					pending = scanWindow{mergedStart, mergedEnd}
				} else {
					flush()
					pending = scanWindow{matchStart, end}
					hasPending = true
				}
			}
		}
	}
	flush()
	merged := out
	out = make([]scanWindow, 0, len(merged))
	for _, interval := range merged {
		for start := interval.start; start < interval.end; start += maxRegexWindowBytes / 2 {
			end := min(start+maxRegexWindowBytes, interval.end)
			out = append(out, scanWindow{start, end})
			if end == interval.end {
				break
			}
		}
	}
	if len(out) > maxRegexWindowsPerRequest {
		// Preserve candidates from both ends when the per-request budget is hit.
		half := maxRegexWindowsPerRequest / 2
		selected := make([]scanWindow, 0, maxRegexWindowsPerRequest)
		selected = append(selected, out[:half]...)
		selected = append(selected, out[len(out)-half:]...)
		return selected, false
	}
	return out, true
}

func isShortAlphaNumericWord(word string) bool {
	if len(word) == 0 || len(word) > 3 {
		return false
	}
	for i := 0; i < len(word); i++ {
		b := word[i]
		isLetter := b >= 'a' && b <= 'z'
		isDigit := b >= '0' && b <= '9'
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}

func keywordAtWordBoundary(text string, start, end int) bool {
	return (start == 0 || !isWordByte(text[start-1])) && (end == len(text) || !isWordByte(text[end]))
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
