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
	"encoding/hex"

	"github.com/urfave/cli"
)

func SetLongevity(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()

	args := c.Args()
	if len(args) != 1 && len(args) != 2 {
		return cli.ShowCommandHelp(c, "set-longevity")
	}

	longevity := ""

	if len(args) == 2 {
		longevity = args[1]
	}

	id, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}

	return client.SetEntityLongevity(id, longevity)
}

var SetLongevityCommand = cli.Command{
	Name:     "set-longevity",
	Action:   Wrapper(SetLongevity),
	Category: "admin",
	Usage:    "Set an entity's certificate validity duration",
}

// vim: foldmethod=marker
