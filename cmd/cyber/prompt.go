/* {{{ Copyright (c) 2017, Paul R. Tagliamonte <paultag@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package main

import (
	"fmt"

	"crypto/x509/pkix"

	"github.com/chzyer/readline"
)

func confirm(rl *readline.Instance, question string) error {
	rl.SetPrompt(fmt.Sprintf("%s [yn] ", question))
	out, err := rl.ReadlineWithDefault("")
	if err != nil {
		return err
	}
	switch out {
	case "y":
		return nil
	case "n":
		return fmt.Errorf("User declined")
	default:
		return confirm(rl, question)
	}
}

func promptUser(rl *readline.Instance, question string, def string) (string, error) {
	rl.SetPrompt(fmt.Sprintf("%s: ", question))
	return rl.ReadlineWithDefault(def)
}

func promptUserList(rl *readline.Instance, question string, def []string) ([]string, error) {
	ret := ""
	if len(def) >= 1 {
		ret = def[0]
	}
	answer, err := promptUser(rl, question, ret)
	if err != nil {
		return []string{}, err
	}
	if answer == "" {
		return []string{}, nil
	}
	return []string{answer}, nil
}

type questionList struct {
	Prompt string
	Target *[]string
}

func confirmSubjectName(rl *readline.Instance, subject pkix.Name) (*pkix.Name, error) {
	var err error

	subject.CommonName, err = promptUser(rl, "CommonName", subject.CommonName)
	if err != nil {
		return nil, err
	}

	for _, question := range []questionList{
		questionList{Prompt: "Organization", Target: &subject.Organization},
		questionList{Prompt: "OrganizationalUnit", Target: &subject.OrganizationalUnit},
		questionList{Prompt: "Country", Target: &subject.Country},
		questionList{Prompt: "Province", Target: &subject.Province},
		questionList{Prompt: "Locality", Target: &subject.Locality},
	} {
		*(question.Target), err = promptUserList(rl, question.Prompt, *question.Target)
		if err != nil {
			return nil, err
		}
	}

	return &subject, nil
}

// vim: foldmethod=marker
