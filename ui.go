package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Terminal output. Every line goes through say so that a running spinner is
// wiped before the line is printed and redrawn below it on its next tick.

var ui struct {
	mu     sync.Mutex
	active *spinner
}

type spinner struct {
	msg   string
	start time.Time
	done  chan struct{}
	gone  chan struct{}
}

const (
	spinFrames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
	clearLine  = "\r\033[K"
)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func say(prefix, f string, a ...any) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if ui.active != nil {
		fmt.Print(clearLine)
	}
	fmt.Printf(prefix+f+"\n", a...)
}

func step(f string, a ...any) { say("\n▸ ", f, a...) }
func info(f string, a ...any) { say("  ", f, a...) }
func ok(f string, a ...any)   { say("  ✓ ", f, a...) }
func warn(f string, a ...any) { say("  ! ", f, a...) }
func yesNo(b bool) string {
	if b {
		return "installed"
	}
	return "missing"
}

// spin shows "⠹ msg  12s" until the returned stop is called, then removes
// the line; print the result with ok/warn afterwards. When stdout is not a
// terminal the message is printed once as a plain line instead.
func spin(f string, a ...any) (stop func()) {
	msg := fmt.Sprintf(f, a...)
	if !isTerminal(os.Stdout) || os.Getenv("TERM") == "dumb" {
		info("%s", msg)
		return func() {}
	}
	s := &spinner{msg: msg, start: time.Now(), done: make(chan struct{}), gone: make(chan struct{})}
	ui.mu.Lock()
	ui.active = s
	ui.mu.Unlock()
	go s.run()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(s.done)
			<-s.gone
		})
	}
}

func (s *spinner) run() {
	frames := []rune(spinFrames)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for i := 0; ; i++ {
		ui.mu.Lock()
		line := fmt.Sprintf("  %c %s", frames[i%len(frames)], s.msg)
		if el := time.Since(s.start); el >= time.Second {
			line += fmt.Sprintf("  %ds", int(el.Seconds()))
		}
		fmt.Print(clearLine + line)
		ui.mu.Unlock()
		select {
		case <-s.done:
			ui.mu.Lock()
			fmt.Print(clearLine)
			ui.active = nil
			ui.mu.Unlock()
			close(s.gone)
			return
		case <-tick.C:
		}
	}
}

// askTyped makes the user type word to go ahead with something destructive.
func askTyped(word string) bool {
	fmt.Printf("\n  Type %s to continue: ", word)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == word
}

// askNoYes asks on the terminal; only an explicit yes counts.
func askNoYes(f string, a ...any) bool {
	fmt.Printf("  "+f+" [y/N] ", a...)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// askYesNo asks on the terminal; Enter means yes.
func askYesNo(f string, a ...any) bool {
	fmt.Printf("  "+f+" [Y/n] ", a...)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	}
	return false
}
