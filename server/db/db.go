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

package db

import (
	"time"

	"crypto/x509"

	"github.com/jinzhu/gorm"
	"pault.ag/go/cybercom/pb"
)

var (
	EntityStateUnknown  string = ""
	EntityStatePending  string = "PENDING"
	EntityStateApproved string = "APPROVED"
	EntityStateRejected string = "REJECTED"
	EntityStateRevoked  string = "REVOKED"
	EntityStateOneOff   string = "ONEOFF"
)

func PBToEntityState(state pb.Entity_State) string {
	switch state {
	case pb.Entity_UNKNOWN:
		return EntityStateUnknown
	case pb.Entity_PENDING:
		return EntityStatePending
	case pb.Entity_APPROVED:
		return EntityStateApproved
	case pb.Entity_REVOKED:
		return EntityStateRevoked
	case pb.Entity_REJECTED:
		return EntityStateRejected
	case pb.Entity_ONEOFF:
		return EntityStateOneOff
	}
	return EntityStateUnknown
}

func EntityStateToPB(name string) pb.Entity_State {
	state := pb.Entity_UNKNOWN
	switch name {
	case EntityStatePending:
		state = pb.Entity_PENDING
	case EntityStateApproved:
		state = pb.Entity_APPROVED
	case EntityStateRevoked:
		state = pb.Entity_REVOKED
	case EntityStateRejected:
		state = pb.Entity_REJECTED
	case EntityStateUnknown:
		state = pb.Entity_UNKNOWN
	case EntityStateOneOff:
		state = pb.Entity_ONEOFF
	default:
		state = pb.Entity_UNKNOWN
	}
	return state
}

type Entity struct {
	gorm.Model

	Hash  []byte `gorm:"primary_key"`
	State string
	CSR   []byte

	Email        string
	Certificates []Certificate

	Longevity *string
	Expires   *time.Time
}

func (entity Entity) GetCertificates(db *gorm.DB) ([]Certificate, error) {
	cert := []Certificate{}
	query := db.Order("not_after ASC").Where("entity_hash = ?", entity.Hash).Find(&cert)
	if query.RecordNotFound() {
		return nil, nil
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return cert, nil
}

func (entity Entity) GetCertificate(db *gorm.DB) (*Certificate, error) {
	cert := Certificate{}
	query := db.Order("not_after ASC").Where("entity_hash = ?", entity.Hash).Find(&cert)
	if query.RecordNotFound() {
		return nil, nil
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return &cert, nil
}

func GetRevokedCertificates(db *gorm.DB) ([]Certificate, error) {
	certs := []Certificate{}

	if err := db.Order("not_after ASC").Where(
		"entities.state = ? AND certificates.not_after > now()", EntityStateRevoked,
	).Joins(
		"LEFT JOIN entities ON entities.hash = certificates.entity_hash",
	).Find(&certs).Error; err != nil {
		return nil, err
	}

	return certs, nil
}

func (c Entity) ToPb() (*pb.Entity, error) {
	longevity := ""
	if c.Longevity != nil {
		longevity = *c.Longevity
	}
	var expires uint64 = 0
	if c.Expires != nil {
		expires = uint64(c.Expires.Unix())
	}
	return &pb.Entity{
		Id:        &pb.Id{Id: c.Hash},
		State:     EntityStateToPB(c.State),
		Csr:       &pb.CSR{Der: c.CSR},
		Email:     c.Email,
		Longevity: longevity,
		Expires:   expires,
	}, nil
}

func (c Entity) ParseCertificateRequest() (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(c.CSR)
}

type Certificate struct {
	gorm.Model

	Hash        []byte `gorm:"primary_key"`
	Certificate []byte
	Serial      []byte

	EntityHash []byte
	Entity     Entity

	Revoked bool

	NotBefore time.Time
	NotAfter  time.Time
}

func (c Certificate) Pb() (*pb.Certificate, error) {
	return &pb.Certificate{Der: c.Certificate}, nil
}

func (c Certificate) ParseCertificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Certificate)
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Certificate{}, &Entity{}).Error
}

func DropIfExists(db *gorm.DB) error {
	return db.DropTableIfExists(&Certificate{}, &Entity{}).Error
}

// vim: foldmethod=marker
