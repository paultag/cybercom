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

package acl

import (
	"fmt"

	"crypto/x509"
)

var (
	// ACLs must return this error if the peer is not authorized to take
	// an action.
	Unauthorized = fmt.Errorf("Client is Unauthorized to take that action")
)

// ACL Interface. This is used to let the CYBERCOM Server validate any incoming
// RPCs, and ensure the user is Authorized to take this action. The ACL need not
// validate identity (that's been established through x509 Certificate validation).
//
// It's strongly advised that this "fail-closed", meaning, if the view, peer
// or client IP Address is not what is expected and known, it ought to return
// Unauthorized.
type ACL interface {
	// Check to see if action `string` is something that the the peer
	// `x509.Certificate` can preform. Additionally, the IP of the peer is
	// sent to the Authorize method through the final `string` argument.
	Authorize(string, *x509.Certificate, string) error
}

// vim: foldmethod=marker
