package main

import (
	"github.com/PuerkitoBio/goquery"
	"log"
	"strings"
	"testing"
)

func TestReplaceNodesData(t *testing.T) {
	html := `
<html><body><div>aaa aaaa aaaaa a aaa aa</div><div>b bb bbb bbbb</div><div>!  c ! ccc!</div></body></html>
`
	expected := `<div>aaa™ aaaa aaaaa a aaa™ aa</div><div>b bb bbb™ bbbb</div><div>!  c ! ccc™!</div>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		log.Fatal(err)
	}

	body := doc.Find("body")
	node := body.Nodes[0]
	replaceNodesData(node, 3)
	htmlstr, err := body.Html()
	if err != nil {
		t.Error(err)
	}
	htmlstr = strings.TrimSpace(htmlstr)
	if htmlstr != expected {
		t.Errorf("Expected:\n[%s]\ngot:\n[%s]\n", expected, htmlstr)
	}
}
