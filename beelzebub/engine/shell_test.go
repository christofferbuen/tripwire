package SSH

import (
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"strings"
	"testing"
)

func TestVirtualState(t *testing.T) {
	s := newVirtualShell("deploy", "web01")
	fallback := func(string) (string, int) { t.Fatal("unexpected provider call"); return "", 1 }
	tests := []struct {
		in, out string
		code    int
	}{
		{"pwd", "/home/deploy\n", 0},
		{"mkdir -p /tmp/site/assets", "", 0},
		{"cd /tmp/site; pwd; echo $PWD", "/tmp/site\n/tmp/site\n", 0},
		{"echo 'hello world' > 'hello file'; cat 'hello file'", "hello world\n", 0},
		{"printf '%s\\n' next >> 'hello file'; cat 'hello file'", "hello world\nnext\n", 0},
		{"cp 'hello file' copy; mv copy renamed; cat renamed", "hello world\nnext\n", 0},
		{"cd /missing || pwd", "cd: /missing: No such file or directory\n/tmp/site\n", 0},
		{"false && echo bad; echo $?", "1\n", 0},
		{"echo '$PWD'", "$PWD\n", 0},
		{"echo \"$PWD\"", "/tmp/site\n", 0},
		{"rm renamed; cat renamed", "cat: renamed: No such file or directory\n", 1},
		{"echo nope > /etc/hostname", "bash: /etc/hostname: cannot write file\n", 1},
		{"cat /etc/hostname", "web01\n", 0},
		{"hello", "bash: hello: command not found\n", 127},
	}
	for _, test := range tests {
		out, code := s.run(test.in, fallback)
		if out != test.out || code != test.code {
			t.Fatalf("%q => %q,%d; expected %q,%d", test.in, out, code, test.out, test.code)
		}
	}
	if s.prompt() != "deploy@web01:/tmp/site$ " {
		t.Fatal(s.prompt())
	}
	other := newVirtualShell("deploy", "web01")
	if _, ok := other.Files["/tmp/site"]; ok || other.Cwd != other.Home {
		t.Fatal("session state leaked")
	}
}

func TestVirtualBoundsAndNoExecution(t *testing.T) {
	s := newVirtualShell("deploy", "web01")
	calls := 0
	fallback := func(string) (string, int) { calls++; return "bash: temporarily unavailable; try again\n", 75 }
	for _, input := range []string{"echo $(touch /tmp/escape)", "echo `id`", "cat x | sh", "curl example.invalid &", "echo x > /../../etc/hostname"} {
		_, code := s.run(input, fallback)
		if code == 0 {
			t.Fatal(input)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe syntax sent to model")
	}
	_, code := s.run("ps", fallback)
	if code != 75 || calls != 1 {
		t.Fatal("failure not preserved")
	}
	if s.Cwd != s.Home {
		t.Fatal("failure changed state")
	}
	for i := 0; i < 300; i++ {
		s.run("touch /tmp/f"+strings.Repeat("x", i), fallback)
	}
	if len(s.Files) > 256 {
		t.Fatal("file limit exceeded")
	}
	if err := s.put("/tmp/large", virtualNode{Data: strings.Repeat("x", 16385)}); err == nil {
		t.Fatal("file bound missing")
	}
}

func TestTripwireHistoryAndTerminal(t *testing.T) {
	var history []plugin.Message
	for i := 0; i < 1000; i++ {
		history = appendHistory(history, strings.Repeat("c", 1000), strings.Repeat("o", 1000))
	}
	if len(history) > 14 || len(history)%2 != 0 {
		t.Fatal("unbounded history")
	}
	for i := 0; i < len(history); i += 2 {
		if history[i].Role != "user" || history[i+1].Role != "assistant" {
			t.Fatal("split pair")
		}
	}
	if strings.ContainsAny(cleanTerminal("\x1b]52;test\a\u202e"), "\x1b\a\u202e") {
		t.Fatal("terminal controls escaped incorrectly")
	}
}
