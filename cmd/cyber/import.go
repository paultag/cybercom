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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"crypto/x509"

	"github.com/urfave/cli"
)

func Import(c *cli.Context) error {
	certPaths := c.Args()
	if len(certPaths) > 1 {
		return cli.ShowCommandHelp(c, "import")
	}

	var fd *os.File
	if len(certPaths) == 0 {
		fd = os.Stdin
	} else {
		var err error
		fd, err = os.Open(certPaths[0])
		if err != nil {
			return err
		}
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("Bad PEM; not a Certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	store, err := NewStore(c)
	if err != nil {
		return err
	}

	return store.Update(*cert)
}

var ImportCommand = cli.Command{
	Name:   "import",
	Action: Wrapper(Import),
	Usage:  "Import a Certificate into the Store",
}

// vim: foldmethod=marker
