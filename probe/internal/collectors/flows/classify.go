package flows

import "strings"

// Rule maps a domain and every name under it to a service.
type Rule struct {
	Domain   string
	Service  string
	Category string
}

// Classifier names the service of a server name by its longest matching
// domain, so that meet.google.com can belong to another service than
// google.com.
type Classifier struct {
	byDomain map[string]Rule
}

// NewClassifier indexes rules. A later rule for the same domain wins.
func NewClassifier(rules []Rule) *Classifier {
	c := &Classifier{byDomain: map[string]Rule{}}
	for _, r := range rules {
		d := strings.ToLower(strings.Trim(r.Domain, "."))
		if d == "" {
			continue
		}
		r.Domain = d
		c.byDomain[d] = r
	}
	return c
}

// Classify returns the rule for name, trying name itself and then each
// parent domain.
func (c *Classifier) Classify(name string) (Rule, bool) {
	if c == nil {
		return Rule{}, false
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for n != "" {
		if r, ok := c.byDomain[n]; ok {
			return r, true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	return Rule{}, false
}
