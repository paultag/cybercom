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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/jinzhu/gorm"

	"pault.ag/go/cybercom/ca"
	"pault.ag/go/cybercom/policy"
	"pault.ag/go/cybercom/policy/simple"
	"pault.ag/go/cybercom/store"
	"pault.ag/go/cybercom/store/filesystem"
	"pault.ag/go/cybercom/store/hsm"
	"pault.ag/go/cybercom/store/yubikey"
	"pault.ag/go/ykpiv"
)

func LoadConfig(path string) (*Config, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	config := Config{}
	if err := json.NewDecoder(fd).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

type CertificateTemplateConfig struct {
	Country      string `json:"country"`
	Organization string `json:"organization"`
	Locality     string `json"locality"`
	Province     string `json:"province"`
}

type CertificateConfig struct {
	Longevity    string                    `json:"longevity"`
	ReissueGrace string                    `json:"reissue_grace"`
	Template     CertificateTemplateConfig `json:"template"`
}

type DatabaseConfig struct {
	Variant    string `json:"variant"`
	Connection string `json:"connection"`
}

type ACLConfig struct {
	Administrators []string `json:"administrators"`
	PublicViews    []string `json:"public_views"`
	AuthedViews    []string `json:"authed_views"`
	AdminViews     []string `json:"admin_views"`
}

func (d DatabaseConfig) New() (*gorm.DB, error) {
	return gorm.Open(d.Variant, d.Connection)
}

type YubikeyConfig struct {
	Reader string `json:"reader"`
	Slot   string `json:"slot"`
	PIN    string `json:"pin"`
}

func (h YubikeyConfig) GetSlot() (*yubikey.Store, error) {
	var slotId ykpiv.SlotId
	switch h.Slot {
	case "authentication":
		slotId = ykpiv.Authentication
	case "signature":
		slotId = ykpiv.Signature
	default:
		return nil, fmt.Errorf("Unknown slot")
	}

	token, err := ykpiv.New(ykpiv.Options{
		PIN:    &h.PIN,
		Reader: h.Reader,
	})
	if err != nil {
		return nil, err
	}
	slot, err := token.Slot(slotId)
	if err != nil {
		return nil, err
	}
	return yubikey.New(token, slotId, slot)
}

type HSMConfig struct {
	Module           string `json:"module"`
	CertificateLabel string `json:"certificate_label"`
	CertificateFile  string `json:"certificate_file"`
	PrivateKeyLabel  string `json:"private_key_label"`
	TokenLabel       string `json:"token_label"`
	PIN              string `json:"pin"`
}

func (h HSMConfig) Config() (*hsm.Config, error) {
	if h.Module == "" {
		return nil, fmt.Errorf("cybercom: No Module defined, I have a sneaking feeling this is wrong")
	}
	config := hsm.Config{
		Module:           h.Module,
		CertificateLabel: h.CertificateLabel,
		CertificateFile:  h.CertificateFile,
		PrivateKeyLabel:  h.PrivateKeyLabel,
		TokenLabel:       h.TokenLabel,
	}
	if h.PIN != "" {
		config.PIN = &h.PIN
	}
	return &config, nil
}

type FilesystemConfig struct {
	Location string `json:"location"`
}

type Config struct {
	Name           string            `json:"name"`
	Store          string            `json:"store"`
	ServerAddress  string            `json:"server_address"`
	CACertificates []string          `json:"ca_certificates"`
	Certificate    CertificateConfig `json:"certificate"`
	TLS            TLSConfig         `json:"tls"`
	HSM            HSMConfig         `json:"hsm"`
	Yubikey        YubikeyConfig     `json:"ykpiv"`
	Filesystem     FilesystemConfig  `json:"filesystem"`
	Database       DatabaseConfig    `json:"database"`
	ACL            ACLConfig         `json:"acl"`
}

type TLSConfig struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func (c TLSConfig) New() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
}

func (c Config) NewStore() (store.Store, error) {
	switch c.Store {
	case "hsm":
		hsmConfig, err := c.HSM.Config()
		if err != nil {
			return nil, err
		}
		return hsm.New(*hsmConfig)
	case "ykpiv":
		return c.Yubikey.GetSlot()
	case "filesystem":
		return filesystem.New(c.Filesystem.Location)
	default:
		return nil, fmt.Errorf("cybercom: No such store: %s", c.Store)
	}
}

func (c Config) Certificates() ([]*x509.Certificate, error) {
	caCertificates := []*x509.Certificate{}

	for _, path := range c.CACertificates {
		fmt.Printf("Loading Certificate: %s\n", path)
		fd, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fd.Close()
		pemData, err := ioutil.ReadAll(fd)
		if err != nil {
			return nil, err
		}
		derDataBlock, _ := pem.Decode(pemData)
		cert, err := x509.ParseCertificate(derDataBlock.Bytes)
		if err != nil {
			return nil, err
		}
		caCertificates = append(caCertificates, cert)
		fd.Close()
	}
	return caCertificates, nil
}

func (c Config) CACertPool() (*x509.CertPool, error) {
	certs, err := c.Certificates()
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	for _, cert := range certs {
		caCertPool.AddCert(cert)
	}
	return caCertPool, nil
}

func (c Config) NewPreparer() (policy.Preparer, error) {
	duration, err := time.ParseDuration(c.Certificate.Longevity)
	if err != nil {
		return nil, err
	}
	return simple.NewPreparer(duration, 16), nil
}

func (c Config) NewCA() (*ca.CA, error) {
	store, err := c.NewStore()
	if err != nil {
		return nil, err
	}

	preparer, err := c.NewPreparer()
	if err != nil {
		return nil, err
	}

	return ca.New(store, preparer)
}

// vim: foldmethod=marker
