package rulesets

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/example/wafplatform/edge/internal/waf"
)

//go:embed *.yml
var embedded embed.FS

func LoadEmbedded(maxRegexBytes int) ([]waf.Rule, error) {
	files, err := fs.Glob(embedded, "*.yml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var all []waf.Rule
	for _, name := range files {
		file, err := embedded.Open(name)
		if err != nil {
			return nil, err
		}
		rules, loadErr := waf.LoadYAML(file, maxRegexBytes)
		closeErr := file.Close()
		if loadErr != nil {
			return nil, fmt.Errorf("load managed ruleset %s: %w", name, loadErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		all = append(all, rules...)
	}
	return all, nil
}
