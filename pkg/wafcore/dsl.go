package wafcore

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type ValueKind uint8

const (
	KindInvalid ValueKind = iota
	KindString
	KindNumber
	KindBool
	KindIP
	KindCIDR
	KindList
)

type Ctx interface {
	String(field string) string
	Number(field string) float64
	IP(field string) net.IP
	Header(name string) string
	Cookie(name string) string
}

type Limits struct{ MaxExpressionBytes, MaxNodes, MaxRegexBytes int }

func DefaultLimits() Limits {
	return Limits{MaxExpressionBytes: 4096, MaxNodes: 512, MaxRegexBytes: 256}
}

type Position struct{ Line, Column int }
type CompileError struct {
	Pos     Position
	Message string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("line %d, column %d: %s", e.Pos.Line, e.Pos.Column, e.Message)
}

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokNumber
	tokIP
	tokCIDR
	tokOperator
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokLBracket
	tokRBracket
	tokComma
)

type token struct {
	kind tokenKind
	text string
	pos  Position
}

type lexer struct {
	src          string
	i, line, col int
}

func newLexer(src string) *lexer { return &lexer{src: src, line: 1, col: 1} }
func (l *lexer) advance() byte {
	b := l.src[l.i]
	l.i++
	if b == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return b
}
func (l *lexer) tokens() ([]token, error) {
	out := []token{}
	for {
		for l.i < len(l.src) && (l.src[l.i] == ' ' || l.src[l.i] == '\t' || l.src[l.i] == '\r' || l.src[l.i] == '\n') {
			l.advance()
		}
		pos := Position{l.line, l.col}
		if l.i >= len(l.src) {
			return append(out, token{kind: tokEOF, pos: pos}), nil
		}
		b := l.src[l.i]
		if isDigit(b) {
			start := l.i
			for l.i < len(l.src) && strings.ContainsRune("0123456789./:", rune(l.src[l.i])) {
				l.advance()
			}
			text := l.src[start:l.i]
			if strings.Contains(text, "/") {
				if _, _, err := net.ParseCIDR(text); err != nil {
					return nil, &CompileError{Pos: pos, Message: "invalid CIDR literal"}
				}
				out = append(out, token{kind: tokCIDR, text: text, pos: pos})
				continue
			}
			if strings.Contains(text, ".") && net.ParseIP(text) != nil {
				out = append(out, token{kind: tokIP, text: text, pos: pos})
				continue
			}
			out = append(out, token{kind: tokNumber, text: text, pos: pos})
			continue
		}
		if isIdentStart(b) {
			start := l.i
			l.advance()
			for l.i < len(l.src) && (isIdentPart(l.src[l.i]) || l.src[l.i] == '.') {
				l.advance()
			}
			out = append(out, token{kind: tokIdent, text: l.src[start:l.i], pos: pos})
			continue
		}
		if b == '\'' {
			l.advance()
			var sb strings.Builder
			closed := false
			for l.i < len(l.src) {
				c := l.advance()
				if c == '\\' {
					if l.i >= len(l.src) {
						break
					}
					n := l.advance()
					switch n {
					case '\\', '\'':
						sb.WriteByte(n)
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					default:
						return nil, &CompileError{Pos: pos, Message: "unsupported string escape"}
					}
					continue
				}
				if c == '\'' {
					closed = true
					break
				}
				sb.WriteByte(c)
			}
			if !closed {
				return nil, &CompileError{Pos: pos, Message: "unterminated string literal"}
			}
			out = append(out, token{kind: tokString, text: sb.String(), pos: pos})
			continue
		}
		if strings.ContainsRune("=<>!", rune(b)) {
			start := l.i
			l.advance()
			if l.i < len(l.src) && l.src[l.i] == '=' {
				l.advance()
			}
			op := l.src[start:l.i]
			if op == "=" || op == "!" {
				return nil, &CompileError{Pos: pos, Message: "expected == or != operator"}
			}
			out = append(out, token{kind: tokOperator, text: op, pos: pos})
			continue
		}
		switch b {
		case '(':
			l.advance()
			out = append(out, token{kind: tokLParen, text: "(", pos: pos})
		case ')':
			l.advance()
			out = append(out, token{kind: tokRParen, text: ")", pos: pos})
		case '{':
			l.advance()
			out = append(out, token{kind: tokLBrace, text: "{", pos: pos})
		case '}':
			l.advance()
			out = append(out, token{kind: tokRBrace, text: "}", pos: pos})
		case '[':
			l.advance()
			out = append(out, token{kind: tokLBracket, text: "[", pos: pos})
		case ']':
			l.advance()
			out = append(out, token{kind: tokRBracket, text: "]", pos: pos})
		case ',':
			l.advance()
			out = append(out, token{kind: tokComma, text: ",", pos: pos})
		default:
			return nil, &CompileError{Pos: pos, Message: fmt.Sprintf("unexpected character %q", b)}
		}
	}
}
func isIdentStart(b byte) bool { return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isIdentPart(b byte) bool  { return isIdentStart(b) || isDigit(b) }
func isDigit(b byte) bool      { return b >= '0' && b <= '9' }

type node interface{ position() Position }
type literalNode struct {
	pos  Position
	kind ValueKind
	s    string
	n    float64
	b    bool
}

func (n *literalNode) position() Position { return n.pos }

type fieldNode struct {
	pos       Position
	name, arg string
	kind      ValueKind
}

func (n *fieldNode) position() Position { return n.pos }

type listNode struct {
	pos   Position
	items []node
}

func (n *listNode) position() Position { return n.pos }

type unaryNode struct {
	pos Position
	op  string
	x   node
}

func (n *unaryNode) position() Position { return n.pos }

type binaryNode struct {
	pos  Position
	op   string
	l, r node
}

func (n *binaryNode) position() Position { return n.pos }

type parser struct {
	tokens             []token
	i, nodes, maxNodes int
}

func (p *parser) cur() token { return p.tokens[p.i] }
func (p *parser) take() token {
	t := p.cur()
	if p.i < len(p.tokens)-1 {
		p.i++
	}
	return t
}
func (p *parser) expect(k tokenKind, what string) (token, error) {
	t := p.cur()
	if t.kind != k {
		return t, &CompileError{Pos: t.pos, Message: "expected " + what}
	}
	return p.take(), nil
}
func (p *parser) new(n node) (node, error) {
	p.nodes++
	if p.maxNodes > 0 && p.nodes > p.maxNodes {
		return nil, &CompileError{Pos: n.position(), Message: "expression exceeds node limit"}
	}
	return n, nil
}
func (p *parser) parse(minBP int) (node, error) {
	t := p.take()
	var left node
	switch t.kind {
	case tokLParen:
		x, e := p.parse(0)
		if e != nil {
			return nil, e
		}
		if _, e = p.expect(tokRParen, "')'"); e != nil {
			return nil, e
		}
		left = x
	case tokString:
		left = &literalNode{pos: t.pos, kind: KindString, s: t.text}
	case tokNumber:
		n, e := strconv.ParseFloat(t.text, 64)
		if e != nil {
			return nil, &CompileError{Pos: t.pos, Message: "invalid number"}
		}
		left = &literalNode{pos: t.pos, kind: KindNumber, n: n}
	case tokIP:
		left = &literalNode{pos: t.pos, kind: KindIP, s: t.text}
	case tokCIDR:
		left = &literalNode{pos: t.pos, kind: KindCIDR, s: t.text}
	case tokIdent:
		if t.text == "not" {
			x, e := p.parse(30)
			if e != nil {
				return nil, e
			}
			left = &unaryNode{pos: t.pos, op: "not", x: x}
			break
		}
		if t.text == "true" || t.text == "false" {
			left = &literalNode{pos: t.pos, kind: KindBool, b: t.text == "true"}
			break
		}
		if p.cur().kind == tokLParen {
			if t.text != "lower" && t.text != "url_decode" && t.text != "len" {
				return nil, &CompileError{Pos: t.pos, Message: "unknown function " + t.text}
			}
			p.take()
			arg, e := p.parse(0)
			if e != nil {
				return nil, e
			}
			if _, e = p.expect(tokRParen, "')'"); e != nil {
				return nil, e
			}
			left = &callNode{pos: t.pos, name: t.text, arg: arg}
			break
		}
		if t.text == "http.header" || t.text == "http.cookie" {
			if _, e := p.expect(tokLBracket, "'['"); e != nil {
				return nil, e
			}
			arg, e := p.expect(tokString, "single-quoted field name")
			if e != nil {
				return nil, e
			}
			if _, e = p.expect(tokRBracket, "']'"); e != nil {
				return nil, e
			}
			name := arg.text
			if t.text == "http.header" {
				name = strings.ToLower(name)
			}
			left = &fieldNode{pos: t.pos, name: t.text, arg: name, kind: KindString}
			break
		}
		kind, ok := fieldTypes[t.text]
		if !ok {
			return nil, &CompileError{Pos: t.pos, Message: "unknown field " + t.text}
		}
		left = &fieldNode{pos: t.pos, name: t.text, kind: kind}
	case tokLBrace:
		items := []node{}
		if p.cur().kind != tokRBrace {
			for {
				x, e := p.parse(0)
				if e != nil {
					return nil, e
				}
				items = append(items, x)
				if p.cur().kind != tokComma {
					break
				}
				p.take()
			}
		}
		if _, e := p.expect(tokRBrace, "'}'"); e != nil {
			return nil, e
		}
		left = &listNode{pos: t.pos, items: items}
	default:
		return nil, &CompileError{Pos: t.pos, Message: "expected expression"}
	}
	var e error
	left, e = p.new(left)
	if e != nil {
		return nil, e
	}
	for {
		op := p.cur()
		bp, opText := bindingPower(op)
		if bp < minBP {
			break
		}
		p.take()
		if op.kind == tokIdent && (op.text == "contains" || op.text == "starts_with" || op.text == "ends_with" || op.text == "matches" || op.text == "in" || op.text == "in_cidr") {
			opText = op.text
		}
		right, e := p.parse(bp + 1)
		if e != nil {
			return nil, e
		}
		left, e = p.new(&binaryNode{pos: op.pos, op: opText, l: left, r: right})
		if e != nil {
			return nil, e
		}
	}
	return left, nil
}
func bindingPower(t token) (int, string) {
	if t.kind == tokIdent {
		switch t.text {
		case "or":
			return 10, t.text
		case "and":
			return 20, t.text
		case "contains", "starts_with", "ends_with", "matches", "in", "in_cidr":
			return 40, t.text
		}
	}
	if t.kind == tokOperator {
		switch t.text {
		case "==", "!=", "<", ">", "<=", ">=":
			return 40, t.text
		}
	}
	return -1, ""
}

type callNode struct {
	pos  Position
	name string
	arg  node
}

func (n *callNode) position() Position { return n.pos }

var fieldTypes = map[string]ValueKind{
	"http.host": KindString, "http.method": KindString, "http.path": KindString, "http.query": KindString, "http.uri": KindString, "http.user_agent": KindString, "http.referer": KindString, "http.body": KindString, "req.size": KindNumber, "ip.src": KindIP, "ip.geo.country": KindString, "ip.geo.asn": KindNumber, "tls.ja3": KindString, "tls.ja4": KindString, "bot.score": KindNumber, "waf.score": KindNumber,
}

// ExpressionUsesField reports whether an expression contains a field token,
// excluding text inside quoted literals.
func ExpressionUsesField(expression, field string) bool {
	tokens, err := newLexer(expression).tokens()
	if err != nil {
		return false
	}
	for _, token := range tokens {
		if token.kind == tokIdent && token.text == field {
			return true
		}
	}
	return false
}

func Compile(expression string, limits Limits) (func(Ctx) bool, error) {
	defaults := DefaultLimits()
	if limits.MaxExpressionBytes <= 0 {
		limits.MaxExpressionBytes = defaults.MaxExpressionBytes
	}
	if limits.MaxNodes <= 0 {
		limits.MaxNodes = defaults.MaxNodes
	}
	if limits.MaxRegexBytes <= 0 {
		limits.MaxRegexBytes = defaults.MaxRegexBytes
	}
	if len(expression) > limits.MaxExpressionBytes {
		return nil, &CompileError{Pos: Position{1, 1}, Message: "expression exceeds byte limit"}
	}
	ts, e := newLexer(expression).tokens()
	if e != nil {
		return nil, e
	}
	p := parser{tokens: ts, maxNodes: limits.MaxNodes}
	root, e := p.parse(0)
	if e != nil {
		return nil, e
	}
	if p.cur().kind != tokEOF {
		return nil, &CompileError{Pos: p.cur().pos, Message: "unexpected token " + p.cur().text}
	}
	if k, e := typeOf(root); e != nil {
		return nil, e
	} else if k != KindBool {
		return nil, &CompileError{Pos: root.position(), Message: "expression must evaluate to boolean"}
	}
	opt, e := optimize(root, limits)
	if e != nil {
		return nil, e
	}
	return compileNode(opt), nil
}

func typeOf(n node) (ValueKind, error) {
	switch x := n.(type) {
	case *literalNode:
		return x.kind, nil
	case *fieldNode:
		return x.kind, nil
	case *callNode:
		k, e := typeOf(x.arg)
		if e != nil {
			return KindInvalid, e
		}
		if x.name == "len" {
			if k != KindString {
				return KindInvalid, &CompileError{Pos: x.pos, Message: "len() requires a string"}
			}
			return KindNumber, nil
		}
		if k != KindString {
			return KindInvalid, &CompileError{Pos: x.pos, Message: x.name + "() requires a string"}
		}
		return KindString, nil
	case *listNode:
		if len(x.items) == 0 {
			return KindList, nil
		}
		kind, e := typeOf(x.items[0])
		if e != nil {
			return KindInvalid, e
		}
		for _, i := range x.items[1:] {
			k, e := typeOf(i)
			if e != nil {
				return KindInvalid, e
			}
			if k != kind {
				return KindInvalid, &CompileError{Pos: i.position(), Message: "list elements must have the same type"}
			}
		}
		return KindList, nil
	case *unaryNode:
		k, e := typeOf(x.x)
		if e != nil {
			return KindInvalid, e
		}
		if k != KindBool {
			return KindInvalid, &CompileError{Pos: x.pos, Message: "not requires a boolean"}
		}
		return KindBool, nil
	case *binaryNode:
		return binaryType(x)
	default:
		return KindInvalid, &CompileError{Pos: n.position(), Message: "invalid syntax tree"}
	}
}
func binaryType(x *binaryNode) (ValueKind, error) {
	a, e := typeOf(x.l)
	if e != nil {
		return KindInvalid, e
	}
	b, e := typeOf(x.r)
	if e != nil {
		return KindInvalid, e
	}
	switch x.op {
	case "and", "or":
		if a != KindBool || b != KindBool {
			return KindInvalid, &CompileError{Pos: x.pos, Message: x.op + " requires boolean operands"}
		}
	case "==", "!=":
		if a != b && a != KindList && b != KindList {
			return KindInvalid, &CompileError{Pos: x.pos, Message: "comparison operands have incompatible types"}
		}
	case "<", ">", "<=", ">=":
		if a != b || (a != KindNumber && a != KindString) {
			return KindInvalid, &CompileError{Pos: x.pos, Message: "ordering requires two numbers or two strings"}
		}
	case "contains", "starts_with", "ends_with", "matches":
		if a != KindString || b != KindString {
			return KindInvalid, &CompileError{Pos: x.pos, Message: x.op + " requires string operands"}
		}
	case "in":
		if b != KindList {
			return KindInvalid, &CompileError{Pos: x.pos, Message: "in requires a set on the right"}
		}
		if len(x.r.(*listNode).items) > 0 {
			item, _ := typeOf(x.r.(*listNode).items[0])
			if item != a && (a != KindIP || item != KindCIDR) {
				return KindInvalid, &CompileError{Pos: x.pos, Message: "in set element type does not match left operand"}
			}
		}
	case "in_cidr":
		if a != KindIP || b != KindList {
			return KindInvalid, &CompileError{Pos: x.pos, Message: "in_cidr requires an IP and a CIDR set"}
		}
		for _, item := range x.r.(*listNode).items {
			v, ok := item.(*literalNode)
			if !ok || v.kind != KindCIDR {
				return KindInvalid, &CompileError{Pos: item.position(), Message: "in_cidr set values must be CIDR strings"}
			}
		}
	}
	return KindBool, nil
}

type evalValue struct {
	k    ValueKind
	s    string
	n    float64
	b    bool
	ip   net.IP
	list []evalValue
	re   *regexp.Regexp
}

func eval(n node, c Ctx) evalValue {
	switch x := n.(type) {
	case *literalNode:
		v := evalValue{k: x.kind, s: x.s, n: x.n, b: x.b}
		if x.kind == KindIP {
			v.ip = net.ParseIP(x.s)
		}
		return v
	case *fieldNode:
		if x.name == "http.header" {
			return evalValue{k: KindString, s: c.Header(x.arg)}
		}
		if x.name == "http.cookie" {
			return evalValue{k: KindString, s: c.Cookie(x.arg)}
		}
		switch x.kind {
		case KindNumber:
			return evalValue{k: x.kind, n: c.Number(x.name)}
		case KindIP:
			return evalValue{k: x.kind, ip: c.IP(x.name)}
		default:
			return evalValue{k: x.kind, s: c.String(x.name)}
		}
	case *callNode:
		v := eval(x.arg, c)
		switch x.name {
		case "lower":
			v.s = strings.ToLower(v.s)
		case "url_decode":
			if d, e := url.QueryUnescape(v.s); e == nil {
				v.s = d
			}
		case "len":
			return evalValue{k: KindNumber, n: float64(len(v.s))}
		}
		return v
	case *listNode:
		v := evalValue{k: KindList}
		for _, i := range x.items {
			v.list = append(v.list, eval(i, c))
		}
		return v
	case *unaryNode:
		return evalValue{k: KindBool, b: !eval(x.x, c).b}
	case *binaryNode:
		if x.op == "and" {
			a := eval(x.l, c)
			return evalValue{k: KindBool, b: a.b && eval(x.r, c).b}
		}
		if x.op == "or" {
			a := eval(x.l, c)
			return evalValue{k: KindBool, b: a.b || eval(x.r, c).b}
		}
		a, b := eval(x.l, c), eval(x.r, c)
		switch x.op {
		case "==":
			return evalValue{k: KindBool, b: equal(a, b)}
		case "!=":
			return evalValue{k: KindBool, b: !equal(a, b)}
		case "<":
			return evalValue{k: KindBool, b: less(a, b)}
		case ">":
			return evalValue{k: KindBool, b: less(b, a)}
		case "<=":
			return evalValue{k: KindBool, b: !less(b, a)}
		case ">=":
			return evalValue{k: KindBool, b: !less(a, b)}
		case "contains":
			return evalValue{k: KindBool, b: strings.Contains(a.s, b.s)}
		case "starts_with":
			return evalValue{k: KindBool, b: strings.HasPrefix(a.s, b.s)}
		case "ends_with":
			return evalValue{k: KindBool, b: strings.HasSuffix(a.s, b.s)}
		case "matches":
			re := b.re
			if re == nil {
				re, _ = regexp.Compile(b.s)
			}
			return evalValue{k: KindBool, b: re != nil && re.MatchString(a.s)}
		case "in":
			for _, item := range b.list {
				if item.k == KindCIDR && a.k == KindIP {
					_, cidr, e := net.ParseCIDR(item.s)
					if e == nil && cidr.Contains(a.ip) {
						return evalValue{k: KindBool, b: true}
					}
				}
				if equal(a, item) {
					return evalValue{k: KindBool, b: true}
				}
			}
			return evalValue{k: KindBool}
		case "in_cidr":
			for _, item := range b.list {
				_, cidr, e := net.ParseCIDR(item.s)
				if e == nil && cidr.Contains(a.ip) {
					return evalValue{k: KindBool, b: true}
				}
			}
			return evalValue{k: KindBool}
		}
	}
	return evalValue{}
}
func equal(a, b evalValue) bool {
	if a.k == KindList && b.k != KindList {
		for _, x := range a.list {
			if equal(x, b) {
				return true
			}
		}
		return false
	}
	if b.k == KindList && a.k != KindList {
		for _, x := range b.list {
			if equal(a, x) {
				return true
			}
		}
		return false
	}
	switch a.k {
	case KindString, KindCIDR:
		return a.s == b.s
	case KindIP:
		if a.ip != nil && b.ip != nil {
			return a.ip.Equal(b.ip)
		}
		return a.s == b.s
	case KindNumber:
		return a.n == b.n
	case KindBool:
		return a.b == b.b
	}
	return false
}
func less(a, b evalValue) bool {
	if a.k == KindNumber {
		return a.n < b.n
	}
	return a.s < b.s
}

func optimize(n node, l Limits) (node, error) {
	switch x := n.(type) {
	case *callNode:
		a, e := optimize(x.arg, l)
		if e != nil {
			return nil, e
		}
		x.arg = a
		return x, nil
	case *unaryNode:
		a, e := optimize(x.x, l)
		if e != nil {
			return nil, e
		}
		x.x = a
		if v, ok := a.(*literalNode); ok && v.kind == KindBool {
			return &literalNode{pos: x.pos, kind: KindBool, b: !v.b}, nil
		}
		return x, nil
	case *binaryNode:
		a, e := optimize(x.l, l)
		if e != nil {
			return nil, e
		}
		b, e := optimize(x.r, l)
		if e != nil {
			return nil, e
		}
		x.l, x.r = a, b
		if x.op == "matches" {
			v, ok := b.(*literalNode)
			if !ok {
				return nil, &CompileError{Pos: b.position(), Message: "matches pattern must be a string literal"}
			}
			if len(v.s) > l.MaxRegexBytes {
				return nil, &CompileError{Pos: v.pos, Message: "regex exceeds byte limit"}
			}
			re, e := regexp.Compile(v.s)
			if e != nil {
				return nil, &CompileError{Pos: v.pos, Message: "invalid RE2 pattern: " + e.Error()}
			}
			b = &compiledRegexNode{pos: v.pos, pattern: v.s, re: re}
			x.r = b
		}
		if x.op == "and" || x.op == "or" {
			if _, ok := a.(*binaryNode); !ok {
				if nodeCost(a) > nodeCost(b) {
					x.l, x.r = x.r, x.l
				}
			}
		}
		return x, nil
	}
	return n, nil
}

type compiledRegexNode struct {
	pos     Position
	pattern string
	re      *regexp.Regexp
}

func (n *compiledRegexNode) position() Position { return n.pos }
func nodeCost(n node) int {
	switch x := n.(type) {
	case *binaryNode:
		if x.op == "matches" {
			return 10
		}
		return 2
	case *callNode:
		return 5
	case *fieldNode:
		if x.name == "http.body" {
			return 8
		}
		return 1
	}
	return 0
}
func compileNode(n node) func(Ctx) bool {
	if x, ok := n.(*binaryNode); ok {
		if x.op == "and" {
			left, right := compileNode(x.l), compileNode(x.r)
			return func(c Ctx) bool { return left(c) && right(c) }
		}
		if x.op == "or" {
			left, right := compileNode(x.l), compileNode(x.r)
			return func(c Ctx) bool { return left(c) || right(c) }
		}
	}
	return func(c Ctx) bool { return eval(n, c).b }
}

// Action models the rule effect; condition expressions compile to bool and do not execute effects.
type Action struct {
	Type       string `json:"type" yaml:"type"`
	StatusCode int    `json:"status_code,omitempty" yaml:"status_code,omitempty"`
	Policy     string `json:"policy,omitempty" yaml:"policy,omitempty"`
	Tag        string `json:"tag,omitempty" yaml:"tag,omitempty"`
	Phase      string `json:"phase,omitempty" yaml:"phase,omitempty"`
}

func (a Action) Validate() error {
	switch a.Type {
	case "allow", "challenge", "log":
		return nil
	case "block":
		if a.StatusCode != 0 && (a.StatusCode < 400 || a.StatusCode > 599) {
			return fmt.Errorf("block status_code must be between 400 and 599")
		}
		return nil
	case "rate_limit":
		if a.Policy == "" {
			return fmt.Errorf("rate_limit action requires policy")
		}
		return nil
	case "tag":
		if a.Tag == "" {
			return fmt.Errorf("tag action requires tag")
		}
		return nil
	case "skip":
		if a.Phase == "" {
			return fmt.Errorf("skip action requires phase")
		}
		return nil
	default:
		return fmt.Errorf("unsupported action %q", a.Type)
	}
}

// Accessors let callers implement request-scoped fields without coupling wafcore to edge.
type MapCtx struct {
	Strings map[string]string
	Numbers map[string]float64
	IPs     map[string]net.IP
	Headers map[string]string
	Cookies map[string]string
}

func (c MapCtx) String(f string) string {
	if f == "http.header" {
		return ""
	}
	if f == "http.cookie" {
		return ""
	}
	return c.Strings[f]
}
func (c MapCtx) Number(f string) float64 { return c.Numbers[f] }
func (c MapCtx) IP(f string) net.IP      { return c.IPs[f] }
func (c MapCtx) Header(n string) string  { return c.Headers[strings.ToLower(n)] }
func (c MapCtx) Cookie(n string) string  { return c.Cookies[n] }
