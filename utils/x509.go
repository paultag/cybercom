/* {{{ Copyright (c) 2017r Paul R. Tagliamonte <paultag@gmail.com>
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

package utils

import (
	"fmt"
	"strings"

	"crypto/x509/pkix"
)

type subjectChunk struct {
	Name  string
	Blobs []string
}

func SubjectToString(name pkix.Name) string {
	chunks := []string{}
	for _, chunk := range []subjectChunk{
		subjectChunk{Name: "C", Blobs: name.Country},
		subjectChunk{Name: "O", Blobs: name.Organization},
		subjectChunk{Name: "OU", Blobs: name.OrganizationalUnit},
		subjectChunk{Name: "L", Blobs: name.Locality},
		subjectChunk{Name: "ST", Blobs: name.Province},
	} {
		for _, blobEntry := range chunk.Blobs {
			chunks = append(chunks, fmt.Sprintf("%s=%s", chunk.Name, blobEntry))
		}
	}

	chunks = append(chunks, fmt.Sprintf("CN=%s", name.CommonName))
	return strings.Join(chunks, ", ")
}

// vim: foldmethod=marker
