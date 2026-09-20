package SSH

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"golang.org/x/term"
)

func cleanTerminal(text string) string {
	var out strings.Builder
	for _, c := range text {
		if c == '\n' || c == '\t' {
			out.WriteRune(c)
		} else if unicode.IsControl(c) || unicode.In(c, unicode.Cf) {
			fmt.Fprintf(&out, "\\u%04x", c)
		} else {
			out.WriteRune(c)
		}
	}
	return out.String()
}

func appendHistory(history []plugin.Message, command, output string) []plugin.Message {
	history = append(history, plugin.Message{Role: "user", Content: command}, plugin.Message{Role: "assistant", Content: output})
	size := func() int {
		n := 0
		for _, m := range history {
			n += len(m.Content)
		}
		return n
	}
	for len(history) > 0 && (len(history) > 14 || size() > 16384) {
		history = history[2:]
	}
	// Copy to release old backing arrays and their retained strings.
	return append([]plugin.Message(nil), history...)
}

func handleTripwire(sess ssh.Session, conf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	id := uuid.New().String()
	host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
	shell := newVirtualShell(sess.User(), cleanTerminal(conf.ServerName))
	var history []plugin.Message // Owned only by this SSH channel; discarded on close.
	trace := func(status, command, output, handler string) {
		event := tracer.Event{Msg: "SSH virtual shell", Protocol: tracer.SSH.String(), Status: status, ID: id, Description: conf.Description, Command: command, CommandOutput: output, Handler: handler}
		if status != tracer.End.String() {
			event.SourceIp = host
			event.SourcePort = port
			event.RemoteAddr = sess.RemoteAddr().String()
			event.User = sess.User()
		}
		tr.TraceEvent(event)
	}
	execute := func(input string) (string, int, string) {
		handler := "virtual-shell"
		modelFailed := false
		fallback := func(command string) (string, int) {
			// Preserve configured static system identities before model fallback.
			for _, c := range conf.Commands {
				if c.Plugin == "" && c.Regex.MatchString(command) {
					return c.Handler + "\n", 0
				}
			}
			cp, ok := plugin.GetCommand(plugins.LLMPluginName)
			if !ok {
				modelFailed = true
				return "bash: temporarily unavailable; try again\n", 75
			}
			cfg := plugins.ConfigFromServiceConf(conf)
			cfg.Prompt += fmt.Sprintf("\nAuthoritative session state: user=%q hostname=%q cwd=%q. This request is read-only; do not claim file or directory changes.", shell.User, shell.Host, shell.Cwd)
			ctx, cancel := context.WithTimeout(sess.Context(), 32*time.Second)
			defer cancel()
			output, err := cp.Execute(ctx, plugin.CommandRequest{Command: command, ClientIP: host, Protocol: "ssh", History: history, Config: cfg})
			handler = "model"
			if err != nil {
				modelFailed = true
				handler = "model-unavailable"
				if errors.Is(err, plugins.ErrRateLimited) {
					handler = "model-rate-limited"
				}
				return "bash: temporarily unavailable; try again\n", 75
			}
			if len(output) > 8192 {
				modelFailed = true
				handler = "model-invalid-output"
				return "bash: temporarily unavailable; try again\n", 75
			}
			if output != "" && !strings.HasSuffix(output, "\n") {
				output += "\n"
			}
			return output, 0
		}
		output, status := shell.run(input, fallback)
		output = cleanTerminal(output)
		if len(output) > 8192 {
			output = "bash: output limit exceeded\n"
			status = 1
		}
		// A failed provider response must not poison the next model request.
		if !modelFailed {
			history = appendHistory(history, input, output)
		}
		return output, status, handler
	}
	if input := sess.RawCommand(); input != "" {
		output, status, handler := execute(input)
		sess.Write([]byte(output))
		trace(tracer.Start.String(), input, output, handler)
		sess.Exit(status)
		return
	}
	trace(tracer.Start.String(), "", "", "")
	defer trace(tracer.End.String(), "", "", "")
	terminal := term.NewTerminal(sess, cleanTerminal(shell.prompt()))
	for {
		input, err := terminal.ReadLine()
		if err != nil {
			return
		}
		if strings.TrimSpace(input) == "exit" || strings.TrimSpace(input) == "logout" {
			sess.Exit(shell.Status)
			return
		}
		output, _, handler := execute(input)
		terminal.Write([]byte(output))
		terminal.SetPrompt(cleanTerminal(shell.prompt()))
		trace(tracer.Interaction.String(), input, output, handler)
	}
}
