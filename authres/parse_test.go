package authres

import (
	"reflect"
	"testing"
)

var parseTests = []msgauthTest{
	{
		name:       "empty",
		value:      "",
		identifier: "",
		results:    nil,
	},
	{
		name:       "no results",
		value:      "example.com 1; none",
		identifier: "example.com",
		results:    nil,
	},
	{
		name: "line return",
		value: "example.com; \r\n" +
			" \t spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		name: "space in quoted value",
		value: "example.com;" +
			"dkim=pass reason=\"good signature\" header.i=@mail-router.example.net;",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Reason: "good signature", Identifier: "@mail-router.example.net"},
		},
	},
	{
		name: "semicolon in quoted value",
		value: "example.com;" +
			"dkim=pass reason=\"good; signature\" header.i=@mail-router.example.net;",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Reason: "good; signature", Identifier: "@mail-router.example.net"},
		},
	},
	{
		name: "basic comment",
		value: "example.com;" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		name: "multiple results",
		value: "example.com;" +
			" auth=pass (cram-md5) smtp.auth=sender@example.com;" +
			" spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		name: "comment in comment",
		value: "example.com;" +
			" auth=pass (cram-md5 (comment inside comment)) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		name: "semicolon in comment",
		value: "example.com;" +
			" auth=pass (cram-md5; comment with semicolon) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		name: "escaped char in comment",
		value: "example.com;" +
			" auth=pass (cram-md5 \\( comment with escaped char) smtp.auth=sender@example.com;",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
		},
	},
	{
		name: "extreme",
		value: "foo.example.net (foobar) 1 (baz);" +
			" dkim (Because I like it) / 1 (One yay) = (wait for it) fail" +
			" policy (A dot can go here) . (like that) expired" +
			" (this surprised me) = (as I wasn't expecting it) 1362471462",
		identifier: "foo.example.net",
		results: []Result{
			&DKIMResult{Value: ResultFail, Reason: "", Domain: "", Identifier: ""},
		},
	},
}

var mustFailParseTests = []msgauthTest{
	{
		name:       "no identifier found",
		value:      " ; ",
		identifier: "",
		results:    nil,
	},
	{
		name:       "unknown version",
		value:      "example.com 2; none",
		identifier: "example.com",
		results:    nil,
	},
}

func TestParse(t *testing.T) {
	for _, test := range append(msgauthTests, parseTests...) {
		t.Run(test.name, func(t *testing.T) {
			identifier, results, err := Parse(test.value)
			if err != nil {
				t.Errorf("Expected no error when parsing header, got: %v", err)
			} else if test.identifier != identifier {
				t.Errorf("Expected identifier to be %q, but got %q", test.identifier, identifier)
			} else if len(test.results) != len(results) {
				t.Errorf("Expected number of results to be %v, but got %v", len(test.results), len(results))
			} else {
				for i := 0; i < len(results); i++ {
					if !reflect.DeepEqual(test.results[i], results[i]) {
						t.Errorf("Expected result to be \n%#v\n but got \n%#v", test.results[i], results[i])
					}
				}
			}
		})
	}
}

func TestParseFail(t *testing.T) {
	for _, test := range mustFailParseTests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := Parse(test.value)
			if err == nil {
				t.Errorf("Expected an error when parsing header, but got none.")
			}
		})
	}
}
