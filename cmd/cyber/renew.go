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

	"github.com/urfave/cli"

	"pault.ag/go/cybercom/store"
)

func Renew(c *cli.Context) error {
	cyStore, err := NewStore(c)
	if err != nil {
		return err
	}

	cert, err := cyStore.Certificate()
	if err != nil && err != store.Uninitialized {
		return err
	}

	if cert == nil {
		return fmt.Errorf("No Certificate in the Store")
	}
	serial := cert.SerialNumber

	client, closer, err := NewClient(c, cyStore)
	if err != nil {
		return err
	}
	defer closer()

	cert, err = client.Renew()
	if err != nil {
		return err
	}

	if cert.SerialNumber.Cmp(serial) == 0 {
		/* If the Serial is the same, we can leave */
		fmt.Printf("No new Certificate\n")
		return nil
	}

	fmt.Printf("Imported new Certificate\n")

	return cyStore.Update(*cert)
}

var RenewCommand = cli.Command{
	Name:   "renew",
	Action: Wrapper(Renew),
	Usage:  "Renew the Certificate in the Store",
}

// vim: foldmethod=marker
