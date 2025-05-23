package authres

type msgauthTest struct {
	name       string
	value      string
	identifier string
	results    []Result
}

var msgauthTests = []msgauthTest{
	{
		name:       "none",
		value:      "example.org; none",
		identifier: "example.org",
		results:    nil,
	},
	{
		name:       "dkim=none",
		value:      "example.com; dkim=none ",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultNone},
		},
	},
	{
		name: "spf=pass",
		value: "example.com;" +
			" spf=pass smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultPass, From: "example.net"},
		},
	},
	{
		name: "spf=fail",
		value: "example.com;" +
			" spf=fail reason=bad smtp.mailfrom=example.net",
		identifier: "example.com",
		results: []Result{
			&SPFResult{Value: ResultFail, Reason: "bad", From: "example.net"},
		},
	},
	{
		name: "auth=pass spf=pass",
		value: "example.com;" +
			" auth=pass smtp.auth=sender@example.com;" +
			" spf=pass smtp.mailfrom=example.com",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultPass, From: "example.com"},
		},
	},
	{
		name: "sender-id=pass",
		value: "example.com;" +
			" sender-id=pass header.from=example.com",
		identifier: "example.com",
		results: []Result{
			&SenderIDResult{Value: ResultPass, HeaderKey: "from", HeaderValue: "example.com"},
		},
	},
	{
		name: "sender-id=hardfail dkim=pass",
		value: "example.com;" +
			" sender-id=hardfail header.from=example.com;" +
			" dkim=pass header.i=sender@example.com",
		identifier: "example.com",
		results: []Result{
			&SenderIDResult{Value: ResultHardFail, HeaderKey: "from", HeaderValue: "example.com"},
			&DKIMResult{Value: ResultPass, Identifier: "sender@example.com"},
		},
	},
	{
		name: "auth=pass spf=hardfail",
		value: "example.com;" +
			" auth=pass smtp.auth=sender@example.com;" +
			" spf=hardfail smtp.mailfrom=example.com",
		identifier: "example.com",
		results: []Result{
			&AuthResult{Value: ResultPass, Auth: "sender@example.com"},
			&SPFResult{Value: ResultHardFail, From: "example.com"},
		},
	},
	{
		name: "dkim=pass dkim=fail",
		value: "example.com;" +
			" dkim=pass header.i=@mail-router.example.net;" +
			" dkim=fail header.i=@newyork.example.com",
		identifier: "example.com",
		results: []Result{
			&DKIMResult{Value: ResultPass, Identifier: "@mail-router.example.net"},
			&DKIMResult{Value: ResultFail, Identifier: "@newyork.example.com"},
		},
	},
}
