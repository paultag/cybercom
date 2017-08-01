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

package server

import (
	"fmt"
	"log"
	"time"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"golang.org/x/net/context"

	"github.com/jinzhu/gorm"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"pault.ag/go/cybercom/acl"
	"pault.ag/go/cybercom/ca"
	"pault.ag/go/cybercom/pb"
	"pault.ag/go/cybercom/policy"
	"pault.ag/go/cybercom/server/db"
)

// Common Error returned if the record is not found in our underlying
// database. This can be handy for ducking missing records without
// eating all errors.
var NotFound = fmt.Errorf("Record not found")

type Options struct {
	// Active connection to the underlying database we'll store and read our
	// Certificates and Entities from. It's important that the underlying
	// database be OK with reading and writing raw bytes, most notibly, this
	// means SQLite will not work.
	Database *gorm.DB

	// The Cybercom ACL helps ensure that only authorized peers can access
	// the relevent API endpoints.
	ACL acl.ACL

	// Cybercom CA that we will issue new Certificates off of.
	CA ca.CA

	// Take CSRs and turn them into x509 Certificates.
	Translator policy.Translator

	// Default for Certifciate longevity; this can be optionally overridden
	// on a per-Entity basis by updating the Database
	ReissueGrace time.Duration

	// Name of this CA Server (something like Strexcorp Synnernists, Inc, or
	// Paul's CA), used for display purposes only.
	Name string

	// Defaults optionally given to the user for prompting for an appropriate
	// Subject for a new Entity.
	CertificateTemplate pkix.Name

	// CA Certificates that we would like clients to know about in order to
	// validate Certificates that we care to have them know about.
	CACertificates []*x509.Certificate
}

// Encapsulated Server
type CybercomServer struct {
	options Options
}

// New {{{

// Create a new CYBERCOM Server, complete with the CA which will issue requests
// for Certificates, the Policy to define the translation step before signing,
// the Translator to turn a CSR into a Certifciate, and the ACL to define
// who can preform what actions.
func New(
	options Options,
) (*CybercomServer, error) {
	server := CybercomServer{options: options}
	return &server, nil
}

// }}}

// CybercomServer {{{

// Helpers {{{

func (c CybercomServer) getClientAddress(ctx context.Context) (string, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("Eeeep! getClientAddress did something funny.")
	}
	return peer.Addr.String(), nil
}

// Get the peer certificate out of the `ctx` object. This is used to tell who
// we're talking to.
func (c CybercomServer) getCertificate(ctx context.Context) (*x509.Certificate, error) {
	peer, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
		if len(tlsInfo.State.VerifiedChains) == 0 {
			return nil, nil
		}
		return tlsInfo.State.VerifiedChains[0][0], nil
	}
	return nil, fmt.Errorf("No TLS Peer Certificate provided")
}

func (c CybercomServer) checkACL(ctx context.Context, action string) error {
	peer, err := c.getCertificate(ctx)
	if err != nil {
		return err
	}

	clientIp, err := c.getClientAddress(ctx)
	if err != nil {
		return err
	}

	err = c.options.ACL.Authorize(action, peer, clientIp)

	peerName := "(Unauthenticated)"
	if peer != nil {
		peerName = peer.Subject.CommonName
	}

	log.Printf("Peer %s attempting to access %s; allowed: %t\n", peerName, action, err == nil)
	return err
}

func (c CybercomServer) getEmail(cert interface{}) (*string, error) {
	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	noEmailError := fmt.Errorf("No Email provided")

	if csr, ok := cert.(x509.CertificateRequest); ok {
		if len(csr.EmailAddresses) >= 1 {
			return &csr.EmailAddresses[0], nil
		}
		for _, entry := range csr.Subject.Names {
			if entry.Type.Equal(emailOID) {
				emailAddress := entry.Value.(string)
				return &emailAddress, nil
			}
		}
		return nil, noEmailError
	}
	return nil, fmt.Errorf("Unknown entry passed to getEmail")
}

func (c CybercomServer) checkCSR(csr x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		return err
	}

	email, err := c.getEmail(csr)
	if err != nil {
		return err
	}

	if email == nil {
		return fmt.Errorf("No email is associated with this Entity")
	}

	return nil
}

func (c CybercomServer) getEntity(id []byte) (*db.Entity, error) {
	entity := db.Entity{}
	query := c.options.Database.First(&entity, "hash = ?", id)
	if query.RecordNotFound() {
		return nil, NotFound
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return &entity, nil
}

// }}}

func (c CybercomServer) Register(ctx context.Context, csr *pb.CSR) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.register"); err != nil {
		return nil, err
	}

	id, err := csr.Hash()
	if err != nil {
		return nil, err
	}

	entity, err := c.getEntity(id)
	if err != nil && err != NotFound {
		return nil, err
	} else if err == nil {
		return entity.ToPb()
	}

	givenCSR, err := csr.CertificateRequest()
	if err != nil {
		return nil, err
	}

	if err := c.checkCSR(*givenCSR); err != nil {
		return nil, err
	}

	email, err := c.getEmail(*givenCSR)
	if err != nil {
		return nil, err
	}

	entity = &db.Entity{
		Hash:      id,
		Email:     *email,
		CSR:       csr.Der,
		State:     db.EntityStatePending,
		Longevity: nil,
	}

	if err := c.options.Database.Create(entity).Error; err != nil {
		return nil, err
	}

	return entity.ToPb()
}

func (c CybercomServer) GetEntity(ctx context.Context, id *pb.Id) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.get-entity"); err != nil {
		return nil, err
	}

	entity, err := c.getEntity(id.Id)
	if err != nil {
		return nil, err
	}
	return entity.ToPb()
}

func (c CybercomServer) GetCertificates(id *pb.Id, stream pb.Cybercom_GetCertificatesServer) error {
	if err := c.checkACL(stream.Context(), "cybercom.get-certificates"); err != nil {
		return err
	}

	entity, err := c.getEntity(id.Id)
	if err != nil {
		return err
	}

	certificates, err := entity.GetCertificates(c.options.Database)
	if err != nil {
		return err
	}

	for _, certificate := range certificates {
		pbCertificate, err := certificate.Pb()
		if err != nil {
			return err
		}
		if err := stream.Send(pbCertificate); err != nil {
			return err
		}
	}

	return nil
}

func (c CybercomServer) GetCertificateBySerial(ctx context.Context, serial *pb.Serial) (*pb.Certificate, error) {
	if err := c.checkACL(ctx, "cybercom.get-certificate-by-serial"); err != nil {
		return nil, err
	}

	cert := db.Certificate{}
	query := c.options.Database.Where("serial = ?", serial.Serial).Find(&cert)
	if query.RecordNotFound() {
		return nil, NotFound
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return cert.Pb()
}

func (c CybercomServer) GetEntityBySerial(ctx context.Context, serial *pb.Serial) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.get-entity-by-serial"); err != nil {
		return nil, err
	}

	dbCert := db.Certificate{}
	query := c.options.Database.Preload("Entity").First(&dbCert, "serial = ?", serial.Serial)
	if query.RecordNotFound() {
		return nil, NotFound
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return dbCert.Entity.ToPb()
}

func (c CybercomServer) GetCertificate(ctx context.Context, id *pb.Id) (*pb.Certificate, error) {
	if err := c.checkACL(ctx, "cybercom.get-certificate"); err != nil {
		return nil, err
	}

	entity, err := c.getEntity(id.Id)
	if err != nil {
		return nil, err
	}

	cert, err := entity.GetCertificate(c.options.Database)
	if err != nil {
		return nil, err
	}

	if cert == nil {
		return &pb.Certificate{Der: []byte{}}, nil
	}

	return cert.Pb()
}

// this is uh, kludgey?
func (c CybercomServer) isEligibleForReissue(entity db.Entity) (*db.Certificate, bool, error) {
	existingCert, err := entity.GetCertificate(c.options.Database)
	if err != nil {
		log.Printf("Hit a problem getting the current Certificate, %s\n", err)
		return nil, false, err
	}

	switch entity.State {
	case db.EntityStateUnknown, db.EntityStatePending, db.EntityStateRejected, db.EntityStateRevoked:
		log.Printf("State is Unknown, Pending, Rejected or Revoked!\n")
		return nil, false, fmt.Errorf("Entity has been revoked")
	case db.EntityStateOneOff:
		if existingCert != nil {
			log.Printf("One-off with a Certificate, bad user!\n")
			return nil, false, fmt.Errorf("Entity is a one-off issuance, and already issued")
		}
	}

	now := time.Now()
	if entity.Expires != nil {
		if entity.Expires.Before(now) {
			log.Printf("Entity has expired out!\n")
			return nil, false, fmt.Errorf("Entity has expired out")
		}
		log.Printf("Entity hasn't expired yet, good sign\n")
	}

	if existingCert == nil {
		/* We've never issued a Certificate for this entity, so let's let
		 * this go ahead */
		return nil, true, nil
	}

	// Is reissueGrace in the future from now still before the NotAfter
	// datetime? Are we after NotBefore?
	if now.Add(c.options.ReissueGrace).Before(existingCert.NotAfter) && now.After(existingCert.NotBefore) {
		/* In the future we ought to do more comprehensive stuff here. */
		log.Printf("We're before %s and after %s, so we're not ready yet.\n",
			existingCert.NotAfter,
			existingCert.NotBefore,
		)
		return existingCert, false, nil
	}
	log.Printf("Seems like we're not overlapping with the current Certificate\n")
	return existingCert, true, nil
}

func (c CybercomServer) issueCertificate(entity db.Entity) (*db.Certificate, error) {
	_, eligible, err := c.isEligibleForReissue(entity)
	if err != nil {
		return nil, err
	}

	if !eligible {
		return nil, fmt.Errorf("There's a valid existing cert; refusing to issue a new one")
	}

	csr, err := x509.ParseCertificateRequest(entity.CSR)
	if err != nil {
		return nil, err
	}
	log.Printf("Attempting to sign peer %s\n", csr.Subject.CommonName)

	cert, err := c.options.Translator.CSRToCertificate(csr)
	if err != nil {
		return nil, err
	}

	if err := c.options.CA.Preparer.Prepare(rand.Reader, cert); err != nil {
		return nil, err
	}

	/* We know what we're doing, and we know a lot about the signing process,
	 * so we're going to override what the Preparer did, and handle the direct
	 * unsafe signoff ourselves */

	cert.EmailAddresses = []string{entity.Email}
	// We're going to explicitly override the email with what we have in the
	// database. The Subject will be copied over by the x509 internals, and
	// only copy the known pkix entries; and not the emailAddress, so we can
	// be sure we got them all.

	if entity.Longevity != nil {
		/* If we have a Longevity, let's override what we told the Preparer
		 * was the default */
		duration, err := time.ParseDuration(*entity.Longevity)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		cert.NotBefore = now
		cert.NotAfter = now.Add(duration)
		log.Printf("Longevity set from %s -> %s\n", cert.NotBefore, cert.NotAfter)
	}

	if entity.Expires != nil {
		/* If we have a hard end date, let's floor the Expiry at that time. */
		if entity.Expires.Before(cert.NotAfter) {
			/* So we're about to issue a cert that expires after the
			 * entity is allowed to have one; so let's go ahead and
			 * floor it */
			cert.NotAfter = *entity.Expires
			log.Printf("Manual expiry cap set to %s\n", cert.NotAfter)
		}
	}

	log.Printf("Preforming a signature over Certificate serial %s\n", cert.SerialNumber)
	signedDer, err := c.options.CA.SignWithoutPreparing(rand.Reader, cert)
	if err != nil {
		return nil, err
	}

	certPb := pb.Certificate{Der: signedDer}
	certHash, err := certPb.Hash()
	if err != nil {
		return nil, err
	}

	issuedCert, err := x509.ParseCertificate(signedDer)
	if err != nil {
		return nil, err
	}

	dbCert := db.Certificate{
		Hash:        certHash,
		Certificate: signedDer,
		Entity:      entity,
		EntityHash:  entity.Hash,
		Revoked:     false,
		Serial:      issuedCert.SerialNumber.Bytes(),
		NotBefore:   issuedCert.NotBefore,
		NotAfter:    issuedCert.NotAfter,
	}

	if err := c.options.Database.Save(&dbCert).Error; err != nil {
		return nil, err
	}

	return &dbCert, nil
}

func (c CybercomServer) IssueCertificate(ctx context.Context, id *pb.Id) (*pb.Certificate, error) {
	if err := c.checkACL(ctx, "cybercom.issue-certificate"); err != nil {
		return nil, err
	}

	entity, err := c.getEntity(id.Id)
	if err != nil {
		return nil, err
	}

	dbCert, err := c.issueCertificate(*entity)
	if err != nil {
		return nil, err
	}

	return dbCert.Pb()
}

func (c CybercomServer) getDBCertificate(cert x509.Certificate) (*db.Certificate, error) {
	hash, err := (&pb.Certificate{Der: cert.Raw}).Hash()
	if err != nil {
		return nil, err
	}

	dbCert := db.Certificate{}
	query := c.options.Database.Preload("Entity").First(&dbCert, "hash = ?", hash)
	if query.RecordNotFound() {
		return nil, NotFound
	}
	if query.Error != nil {
		return nil, query.Error
	}
	return &dbCert, nil
}

func (c CybercomServer) Renew(ctx context.Context, _ *pb.Empty) (*pb.Certificate, error) {
	if err := c.checkACL(ctx, "cybercom.renew"); err != nil {
		return nil, err
	}

	peer, err := c.getCertificate(ctx)
	if err != nil {
		return nil, err
	}

	if peer == nil {
		return nil, fmt.Errorf("No peer certificate provided, can't renew")
	}

	peerCert, err := c.getDBCertificate(*peer)
	if err != nil {
		return nil, err
	}

	existingCert, eligible, err := c.isEligibleForReissue(peerCert.Entity)
	if err != nil {
		return nil, err
	}

	if !eligible || peerCert.Entity.State == db.EntityStateOneOff {
		return existingCert.Pb()
	}

	newCert, err := c.issueCertificate(peerCert.Entity)
	if err != nil {
		return nil, err
	}
	return newCert.Pb()
}

func (c CybercomServer) GetEntities(_ *pb.Empty, stream pb.Cybercom_GetEntitiesServer) error {
	if err := c.checkACL(stream.Context(), "cybercom.get-entities"); err != nil {
		return err
	}

	entities := []db.Entity{}
	if err := c.options.Database.Find(&entities).Error; err != nil {
		return err
	}

	for _, entry := range entities {
		pbEntry, err := entry.ToPb()
		if err != nil {
			return err
		}
		if err := stream.Send(pbEntry); err != nil {
			return err
		}
	}

	return nil
}

func (c CybercomServer) SetEntityExpiry(ctx context.Context, e *pb.Entity) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.set-entity-expiry"); err != nil {
		return nil, err
	}
	entity, err := c.getEntity(e.Id.Id)
	if err != nil {
		return nil, err
	}

	if e.Csr.Der != nil {
		if err := e.Validate(); err != nil {
			return nil, err
		}
	}

	if e.Expires == 0 {
		entity.Expires = nil
	} else {
		// Grrr. Casting to int64 because Unix takes a unit (this is perhaps
		// a good idea for pre-epoch dates)
		tm := time.Unix(int64(e.Expires), 0)
		entity.Expires = &tm
	}

	if err := c.options.Database.Save(entity).Error; err != nil {
		return nil, err
	}

	return entity.ToPb()
}

func (c CybercomServer) SetEntityLongevity(ctx context.Context, e *pb.Entity) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.set-entity-longevity"); err != nil {
		return nil, err
	}
	entity, err := c.getEntity(e.Id.Id)
	if err != nil {
		return nil, err
	}

	if e.Csr.Der != nil {
		if err := e.Validate(); err != nil {
			return nil, err
		}
	}

	if e.Longevity == "" {
		entity.Longevity = nil
	} else {
		_, err := time.ParseDuration(e.Longevity)
		if err != nil {
			return nil, err
		}
		entity.Longevity = &e.Longevity
	}

	if err := c.options.Database.Save(entity).Error; err != nil {
		return nil, err
	}

	return entity.ToPb()
}

func (c CybercomServer) SetEntityState(ctx context.Context, e *pb.Entity) (*pb.Entity, error) {
	if err := c.checkACL(ctx, "cybercom.set-entity-state"); err != nil {
		return nil, err
	}
	entity, err := c.getEntity(e.Id.Id)
	if err != nil {
		return nil, err
	}

	if e.Csr.Der != nil {
		if err := e.Validate(); err != nil {
			return nil, err
		}
	}

	entity.State = db.PBToEntityState(e.State)

	if err := c.options.Database.Save(entity).Error; err != nil {
		return nil, err
	}

	return entity.ToPb()
}

func (c CybercomServer) GetConfiguration(ctx context.Context, e *pb.Empty) (*pb.Configuration, error) {
	if err := c.checkACL(ctx, "cybercom.get-configuration"); err != nil {
		return nil, err
	}

	peer, err := c.getCertificate(ctx)
	if err != nil {
		return nil, err
	}

	pbPeerCert := pb.Certificate{Der: []byte{}}
	var pbEntity *pb.Entity = nil

	if peer != nil {
		pbPeerCert.Der = peer.Raw
		peerCert, err := c.getDBCertificate(*peer)
		if err != nil {
			return nil, err
		}
		pbEntity, err = peerCert.Entity.ToPb()
		if err != nil {
			return nil, err
		}
	}

	return &pb.Configuration{
		Name: c.options.Name,
		RequestTemplate: &pb.Configuration_RequestTemplate{
			Country:      "US",
			Organization: "Bike Shed",
			Locality:     "District of Columbia",
			Province:     "Washington",
		},
		Peer:   &pbPeerCert,
		Entity: pbEntity,
		Ca:     x509ToPbs(c.options.CACertificates),
	}, nil
}

// }}}

func x509ToPbs(certs []*x509.Certificate) []*pb.Certificate {
	ret := []*pb.Certificate{}
	for _, cert := range certs {
		ret = append(ret, x509ToPb(cert))
	}
	return ret
}

func x509ToPb(cert *x509.Certificate) *pb.Certificate {
	return &pb.Certificate{Der: cert.Raw}
}

// vim: foldmethod=marker
