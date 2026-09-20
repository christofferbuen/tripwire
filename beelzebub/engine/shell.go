// Tripwire's deliberately small, in-memory shell. No os/exec, host file IO,
// network clients, or interpreter evaluation belongs in this file.
package SSH

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type virtualNode struct {
	Dir  bool
	Data string
}
type virtualShell struct {
	Cwd, Home, User, Host string
	Files                 map[string]virtualNode
	Status                int
}
type shellToken struct {
	text string
	op   bool
}

func newVirtualShell(user, host string) *virtualShell {
	// Username is display data, never an unrestricted path or terminal control.
	for _, c := range user {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune("_-", c)) {
			user = "deploy"
			break
		}
	}
	if user == "" || len(user) > 32 {
		user = "deploy"
	}
	s := &virtualShell{Home: "/home/" + user, User: user, Host: host, Files: map[string]virtualNode{}}
	s.Cwd = s.Home
	for _, p := range []string{"/", "/home", s.Home, "/tmp", "/var", "/var/www", "/etc", "/bin", "/usr", "/usr/bin", "/proc", "/dev"} {
		s.Files[p] = virtualNode{Dir: true}
	}
	s.Files["/var/www/index.php"] = virtualNode{Data: "<?php echo 'Welcome'; ?>\n"}
	s.Files["/var/www/style.css"] = virtualNode{Data: "body { font-family: sans-serif; }\n"}
	s.Files[s.Home+"/README.txt"] = virtualNode{Data: "Website files are in /var/www.\n"}
	s.Files["/etc/hostname"] = virtualNode{Data: host + "\n"}
	s.Files["/etc/issue"] = virtualNode{Data: "Ubuntu 20.04.6 LTS \\n \\l\n"}
	s.Files["/etc/os-release"] = virtualNode{Data: "NAME=\"Ubuntu\"\nVERSION=\"20.04.6 LTS (Focal Fossa)\"\nID=ubuntu\nVERSION_ID=\"20.04\"\n"}
	return s
}

func (s *virtualShell) prompt() string {
	cwd := s.Cwd
	if cwd == s.Home {
		cwd = "~"
	} else if strings.HasPrefix(cwd, s.Home+"/") {
		cwd = "~" + strings.TrimPrefix(cwd, s.Home)
	}
	return fmt.Sprintf("%s@%s:%s$ ", s.User, s.Host, cwd)
}
func (s *virtualShell) resolve(p string) string {
	if p == "~" {
		p = s.Home
	} else if strings.HasPrefix(p, "~/") {
		p = s.Home + p[1:]
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(s.Cwd, p)
	}
	return path.Clean(p)
}
func (s *virtualShell) variable(name string) string {
	switch name {
	case "PWD":
		return s.Cwd
	case "HOME":
		return s.Home
	case "USER", "LOGNAME":
		return s.User
	case "SHELL":
		return "/bin/bash"
	case "?":
		return strconv.Itoa(s.Status)
	}
	return ""
}

// Parse quotes, escaping, variables and a small set of operators. Substitution,
// pipes and background jobs are rejected, never executed or sent to a model.
func (s *virtualShell) lex(input string) ([]shellToken, error) {
	var tokens []shellToken
	var word strings.Builder
	started := false
	quote := byte(0)
	flush := func() {
		if started {
			tokens = append(tokens, shellToken{text: word.String()})
			word.Reset()
			started = false
		}
	}
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == 0 || c == 27 || c == '`' {
			return nil, fmt.Errorf("unsupported syntax")
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' {
			if i+1 >= len(input) {
				return nil, fmt.Errorf("incomplete escape")
			}
			i++
			word.WriteByte(input[i])
			started = true
			continue
		}
		if c == '"' {
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
				started = true
			}
			continue
		}
		if quote == 0 && c == '\'' {
			quote = '\''
			started = true
			continue
		}
		if c == '$' {
			started = true
			if i+1 < len(input) && input[i+1] == '(' {
				return nil, fmt.Errorf("unsupported substitution")
			}
			j := i + 1
			if j < len(input) && input[j] == '{' {
				end := strings.IndexByte(input[j+1:], '}')
				if end < 0 {
					return nil, fmt.Errorf("bad substitution")
				}
				word.WriteString("\x00" + input[j+1:j+1+end] + "\x00")
				i = j + 1 + end
				continue
			}
			for j < len(input) && ((input[j] >= 'A' && input[j] <= 'Z') || (input[j] >= 'a' && input[j] <= 'z') || input[j] == '_' || input[j] == '?') {
				j++
			}
			if j == i+1 {
				word.WriteByte(c)
			} else {
				word.WriteString("\x00" + input[i+1:j] + "\x00")
				i = j - 1
			}
			continue
		}
		if quote == 0 {
			if c == ' ' || c == '\t' || c == '\r' {
				flush()
				continue
			}
			if strings.ContainsRune(";>&|<\n", rune(c)) {
				flush()
				op := string(c)
				if c == '\n' {
					op = ";"
				}
				if i+1 < len(input) && input[i+1] == c && (c == '>' || c == '&' || c == '|') {
					op += string(c)
					i++
				}
				if op == "|" || op == "&" || op == "<" {
					return nil, fmt.Errorf("unsupported operator")
				}
				tokens = append(tokens, shellToken{text: op, op: true})
				continue
			}
		}
		word.WriteByte(c)
		started = true
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return tokens, nil
}

func (s *virtualShell) writable(p string) bool {
	return strings.HasPrefix(p, s.Home+"/") || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/var/www/")
}
func (s *virtualShell) put(p string, n virtualNode) error {
	if !s.writable(p) {
		return fmt.Errorf("Permission denied")
	}
	parent, ok := s.Files[path.Dir(p)]
	if !ok || !parent.Dir {
		return fmt.Errorf("No such file or directory")
	}
	if old, ok := s.Files[p]; ok && old.Dir != n.Dir {
		return fmt.Errorf("Is a directory")
	}
	bytes := len(n.Data)
	for key, item := range s.Files {
		if key != p {
			bytes += len(item.Data)
		}
	}
	_, exists := s.Files[p]
	if len(n.Data) > 16384 || bytes > 262144 || (!exists && len(s.Files) >= 256) {
		return fmt.Errorf("No space left on device")
	}
	s.Files[p] = n
	return nil
}

func (s *virtualShell) builtin(args []string) (string, int, bool) {
	if len(args) == 0 {
		return "", 0, true
	}
	cmd := args[0]
	a := args[1:]
	fail := func(msg string) (string, int, bool) { return cmd + ": " + msg + "\n", 1, true }
	switch cmd {
	case "pwd":
		return s.Cwd + "\n", 0, true
	case "whoami":
		return s.User + "\n", 0, true
	case "id":
		return fmt.Sprintf("uid=1001(%s) gid=1001(%s) groups=1001(%s)\n", s.User, s.User, s.User), 0, true
	case "hostname":
		return s.Host + "\n", 0, true
	case "true", ":":
		return "", 0, true
	case "false":
		return "", 1, true
	case "cd":
		if len(a) > 1 {
			return fail("too many arguments")
		}
		p := s.Home
		if len(a) == 1 {
			p = s.resolve(a[0])
		}
		n, ok := s.Files[p]
		if !ok {
			return fail(p + ": No such file or directory")
		}
		if !n.Dir {
			return fail(p + ": Not a directory")
		}
		s.Cwd = p
		return "", 0, true
	case "echo":
		suffix := "\n"
		if len(a) > 0 && a[0] == "-n" {
			suffix = ""
			a = a[1:]
		}
		return strings.Join(a, " ") + suffix, 0, true
	case "printf":
		if len(a) == 0 {
			return fail("usage: printf format [arguments]")
		}
		format := strings.ReplaceAll(strings.ReplaceAll(a[0], "\\n", "\n"), "\\t", "\t")
		if format == "%s\n" || format == "%s" {
			if len(a) == 1 {
				return strings.TrimPrefix(format, "%s"), 0, true
			}
			return strings.Join(a[1:], strings.TrimPrefix(format, "%s")) + strings.TrimPrefix(format, "%s"), 0, true
		}
		if strings.Contains(format, "%") {
			return fail("unsupported format")
		}
		return format, 0, true
	case "ls":
		all, long := false, false
		var paths []string
		for _, arg := range a {
			if strings.HasPrefix(arg, "-") {
				for _, c := range strings.TrimPrefix(arg, "-") {
					if c == 'a' || c == 'A' {
						all = true
					} else if c == 'l' {
						long = true
					} else {
						return fail("invalid option")
					}
				}
			} else {
				paths = append(paths, arg)
			}
		}
		if len(paths) == 0 {
			paths = []string{s.Cwd}
		}
		var out []string
		for _, arg := range paths {
			p := s.resolve(arg)
			n, ok := s.Files[p]
			if !ok {
				return fail("cannot access '" + arg + "': No such file or directory")
			}
			names := []string{path.Base(p)}
			if n.Dir {
				names = nil
				for key := range s.Files {
					if key != p && path.Dir(key) == p && (all || !strings.HasPrefix(path.Base(key), ".")) {
						names = append(names, path.Base(key))
					}
				}
				sort.Strings(names)
			}
			for _, name := range names {
				if long {
					key := p
					if n.Dir {
						key = path.Join(p, name)
					}
					node := s.Files[key]
					mode := "-rw-r--r--"
					if node.Dir {
						mode = "drwxr-xr-x"
					}
					out = append(out, fmt.Sprintf("%s 1 %s %s %d Sep 19 12:00 %s", mode, s.User, s.User, len(node.Data), name))
				} else {
					out = append(out, name)
				}
			}
		}
		if len(out) == 0 {
			return "", 0, true
		}
		return strings.Join(out, "\n") + "\n", 0, true
	case "cat":
		var out strings.Builder
		for _, arg := range a {
			p := s.resolve(arg)
			n, ok := s.Files[p]
			if !ok {
				return fail(arg + ": No such file or directory")
			}
			if n.Dir {
				return fail(arg + ": Is a directory")
			}
			out.WriteString(n.Data)
		}
		return out.String(), 0, true
	case "touch", "mkdir":
		if len(a) == 0 {
			return fail("missing operand")
		}
		parents := cmd == "mkdir" && a[0] == "-p"
		if parents {
			a = a[1:]
		}
		for _, arg := range a {
			if strings.HasPrefix(arg, "-") {
				return fail("invalid option")
			}
			p := s.resolve(arg)
			if parents {
				parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
				prefix := ""
				for _, part := range parts {
					prefix += "/" + part
					if n, ok := s.Files[prefix]; ok {
						if !n.Dir {
							return fail(prefix + ": Not a directory")
						}
					} else if err := s.put(prefix, virtualNode{Dir: true}); err != nil {
						return fail(prefix + ": " + err.Error())
					}
				}
				continue
			}
			if n, ok := s.Files[p]; ok {
				if cmd == "mkdir" {
					return fail(arg + ": File exists")
				}
				if n.Dir {
					return "", 0, true
				}
				continue
			}
			if err := s.put(p, virtualNode{Dir: cmd == "mkdir"}); err != nil {
				return fail(arg + ": " + err.Error())
			}
		}
		return "", 0, true
	case "rm":
		recursive, force := false, false
		for len(a) > 0 && strings.HasPrefix(a[0], "-") {
			switch a[0] {
			case "-r", "-R":
				recursive = true
			case "-f":
				force = true
			case "-rf", "-fr":
				recursive = true
				force = true
			default:
				return fail("invalid option")
			}
			a = a[1:]
		}
		if len(a) == 0 && !force {
			return fail("missing operand")
		}
		for _, arg := range a {
			p := s.resolve(arg)
			n, ok := s.Files[p]
			if !ok {
				if force {
					continue
				}
				return fail(arg + ": No such file or directory")
			}
			if !s.writable(p) || p == s.Cwd || strings.HasPrefix(s.Cwd, p+"/") {
				return fail(arg + ": Permission denied")
			}
			if n.Dir && !recursive {
				return fail(arg + ": Is a directory")
			}
			delete(s.Files, p)
			if recursive {
				for key := range s.Files {
					if strings.HasPrefix(key, p+"/") {
						delete(s.Files, key)
					}
				}
			}
		}
		return "", 0, true
	case "cp", "mv":
		if len(a) != 2 {
			return fail("expected source and destination")
		}
		src, dst := s.resolve(a[0]), s.resolve(a[1])
		n, ok := s.Files[src]
		if !ok {
			return fail(a[0] + ": No such file or directory")
		}
		if n.Dir {
			return fail("directory operation not supported")
		}
		if d, ok := s.Files[dst]; ok && d.Dir {
			dst = path.Join(dst, path.Base(src))
		}
		if cmd == "mv" && !s.writable(src) {
			return fail("Permission denied")
		}
		if src == dst {
			return fail("source and destination are the same file")
		}
		if err := s.put(dst, n); err != nil {
			return fail(err.Error())
		}
		if cmd == "mv" {
			delete(s.Files, src)
		}
		return "", 0, true
	case "wget", "curl", "nc", "ssh", "ping", "apt", "apt-get":
		return fail("connection timed out")
	}
	return "", 0, false
}

// A fallback may describe read-only system information, never mutate files.
func modelReadOnly(cmd string) bool {
	switch cmd {
	case "uname", "nproc", "ps", "uptime", "df", "free", "netstat", "ss":
		return true
	}
	return false
}

func (s *virtualShell) run(input string, fallback func(string) (string, int)) (string, int) {
	if len(input) > 16384 {
		return "bash: input too long\n", 2
	}
	tokens, err := s.lex(input)
	if err != nil {
		return "bash: syntax error\n", 2
	}
	var out strings.Builder
	status := s.Status
	separator := ";"
	for len(tokens) > 0 {
		end := 0
		for end < len(tokens) && !(tokens[end].op && (tokens[end].text == ";" || tokens[end].text == "&&" || tokens[end].text == "||")) {
			end++
		}
		chunk := tokens[:end]
		next := ";"
		if end < len(tokens) {
			next = tokens[end].text
			tokens = tokens[end+1:]
		} else {
			tokens = nil
		}
		if len(chunk) == 0 {
			return "bash: syntax error\n", 2
		}
		if (separator == "&&" && status != 0) || (separator == "||" && status == 0) {
			separator = next
			continue
		}
		for i := range chunk {
			if !chunk[i].op {
				parts := strings.Split(chunk[i].text, "\x00")
				for j := 1; j < len(parts); j += 2 {
					parts[j] = s.variable(parts[j])
				}
				chunk[i].text = strings.Join(parts, "")
			}
		}
		var args []string
		target := ""
		appendFile := false
		for i := 0; i < len(chunk); i++ {
			t := chunk[i]
			if t.op {
				if target != "" || (t.text != ">" && t.text != ">>") || i+1 >= len(chunk) || chunk[i+1].op {
					return "bash: syntax error\n", 2
				}
				target = chunk[i+1].text
				appendFile = t.text == ">>"
				i++
			} else {
				args = append(args, t.text)
			}
		}
		// Check redirection before executing a builtin, matching shell failure order.
		destination := ""
		if target != "" {
			destination = s.resolve(target)
			if !s.writable(destination) || !s.Files[path.Dir(destination)].Dir || s.Files[destination].Dir {
				out.WriteString("bash: " + target + ": cannot write file\n")
				status = 1
				separator = next
				continue
			}
		}
		text, code, handled := s.builtin(args)
		if !handled {
			if len(args) > 0 && modelReadOnly(args[0]) && destination == "" {
				text, code = fallback(strings.Join(args, " "))
			} else {
				text = "bash: " + args[0] + ": command not found\n"
				code = 127
			}
		}
		if destination != "" && code == 0 {
			data := text
			if appendFile {
				data = s.Files[destination].Data + data
			}
			if err := s.put(destination, virtualNode{Data: data}); err != nil {
				text = "bash: " + target + ": " + err.Error() + "\n"
				code = 1
			} else {
				text = ""
			}
		}
		out.WriteString(text)
		status = code
		s.Status = status
		separator = next
		if out.Len() > 8192 {
			return "bash: output limit exceeded\n", 1
		}
	}
	s.Status = status
	return out.String(), status
}
