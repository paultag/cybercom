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
	"fmt"

	"github.com/urfave/cli"
)

func Remind(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()
	for _, arg := range c.Args() {
		id, err := hex.DecodeString(arg)
		if err != nil {
			return err
		}

		cert, err := client.GetCertificate(id)
		if err != nil {
			return err
		}

		fmt.Printf(
			"REM %s TAG cert MSG TLS Certificate for %s expires.%%\n",
			cert.NotAfter.Format("2006-01-02"),
			cert.Subject.CommonName,
		)
	}

	return nil
}

var RemindCommand = cli.Command{
	Name:     "remind",
	Action:   Wrapper(Remind),
	Category: "misc",
	Usage:    "Output the latest Certificate's NotAfter date in remind format",
}

// vim: foldmethod=marker
