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
	"fmt"
	"os"

	"github.com/urfave/cli"
)

func Get(c *cli.Context) error {
	store, err := NewStore(c)
	if err != nil {
		return err
	}

	client, closer, err := NewClient(c, store)
	if err != nil {
		return err
	}
	defer closer()

	for _, idString := range c.Args() {
		id, err := hex.DecodeString(idString)
		if err != nil {
			return err
		}
		entity, err := client.GetEntity(id)
		if err != nil {
			return err
		}
		PrintEntityDetails(entity)
		fmt.Printf("\n")
		cert, err := client.GetCertificate(id)
		if err != nil {
			return err
		}
		PrintCertificate(*cert)
		fmt.Printf("\n")
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   cert.Raw,
		}); err != nil {
			return err
		}
	}

	return nil
}

var GetCommand = cli.Command{
	Name:   "get",
	Action: Wrapper(Get),
	Usage:  "Get information about an entity",
}

// vim: foldmethod=marker
