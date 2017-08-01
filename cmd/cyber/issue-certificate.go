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
	"encoding/pem"
	"os"

	"github.com/urfave/cli"
)

func IssueCertificate(c *cli.Context) error {
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

		certificate, err := client.IssueCertificate(id)
		if err != nil {
			return err
		}
		PrintCertificate(*certificate)
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   certificate.Raw,
		}); err != nil {
			return err
		}
	}

	return nil

}

var IssueCertificateCommand = cli.Command{
	Name:     "issue-certificate",
	Action:   Wrapper(IssueCertificate),
	Category: "admin",
	Usage:    "Issue a new Certificate for the specified Entity",
}

// vim: foldmethod=marker
