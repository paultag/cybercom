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
	"strings"

	"github.com/urfave/cli"
)

func Ls(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()

	entities, err := client.GetEntities()
	if err != nil {
		return err
	}

	states := map[string]bool{}
	for _, state := range strings.Split(strings.ToUpper(c.String("state")), ",") {
		states[state] = true
	}

	filterEmail := false
	emails := map[string]bool{}
	for _, email := range strings.Split(c.String("email"), ",") {
		if email == "" {
			continue
		}
		filterEmail = true
		emails[email] = true
	}

	for _, entity := range entities {
		if !states["*"] && !states[entity.State.String()] {
			continue
		}

		if filterEmail && !emails[entity.Email] {
			continue
		}

		if err := PrintEntity(&entity, c.Bool("csr")); err != nil {
			return err
		}
	}
	return nil
}

var LsCommand = cli.Command{
	Name:   "ls",
	Usage:  "List entities known to the server",
	Action: Wrapper(Ls),
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "csr",
			Usage: "Output the x509 CSR we're issued",
		},
		cli.StringFlag{
			Name:  "email",
			Value: "",
			Usage: "comma separated list of emails associated with the entry to filter",
		},
		cli.StringFlag{
			Name:  "state",
			Value: "APPROVED,PENDING,ONEOFF",
			Usage: "comma separated list of states to filter on",
		},
	},
}

// vim: foldmethod=marker
