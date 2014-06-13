package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/coopernurse/gorp"
	_ "github.com/mattn/go-sqlite3"
	"strings"
	"crypto/x509"
)

type Database struct {
	dbmap *gorp.DbMap
}

func parseDbConfig(config string) (string, string, error) {
	configParams := strings.Split(config, ":")
	if len(configParams) != 2 {
		return "", "", errors.New("Invalid config string")
	}
	dbtype, dbconfig := configParams[0], configParams[1]
	return dbtype, dbconfig, nil
}

func dialectAndDriver(dbtype string) (gorp.Dialect, string) {
        switch dbtype {
        case "sqlite":
                return gorp.SqliteDialect{}, "sqlite3"
        }
        panic("invalid dbtype.")
}

func connect(driver string, path string) *sql.DB {
        db, err := sql.Open(driver, path)
        if err != nil {
                panic("Error connecting to db: " + err.Error())
        }
        return db
}

func newDbMap(dbtype string, dbpath string) *gorp.DbMap {
	dialect, driver := dialectAndDriver(dbtype)
	dbmap := &gorp.DbMap{Db: connect(driver, dbpath), Dialect: dialect}
        return dbmap
}

func initDb(dbtype string, dbpath string) (*Database, error) {
	dbmap := newDbMap(dbtype, dbpath)
	dbmap.AddTableWithName(ScanRecord{}, "scan_record").SetKeys(true, "Id")
	dbmap.AddTableWithName(CertChain{}, "cert_chain").SetKeys(true, "Id")
	dbmap.AddTableWithName(VerifiedCertChain{}, "verified_cert_chain").SetKeys(true, "Id")

	err := dbmap.CreateTablesIfNotExists()
	if err != nil {
		return nil, fmt.Errorf("Failed to create database tables: %v", err)
	}

	return &Database{dbmap: dbmap}, nil
}

func (db *Database) Close() {
	db.dbmap.Db.Close()
}

type ScanRecord struct {
	Id                  int64
	Address             string // IPv4/6 address
	Timestamp           int64  // UNIX timestamp (nanoseconds)
	ConnectionSuceeded  bool   // Did the TCP connection succeed?
	Error	            string
	SmtpRecord
}

type SmtpRecord struct {
	ServerName	string
	Ext		string
	Auth		string
	LocalName	string
	DidHello	bool
	HelloError	string
	ExtSTARTTLS	bool
	HasTls		bool
	TlsRecord
}

type TlsRecord struct {
	TlsVersion                 uint16
	HandshakeComplete          bool
	DidResume                  bool
	CipherSuite                uint16
	NegotiatedProtocol         string
	NegotiatedProtocolIsMutual bool
	ServerName                 string
}

type Certificate struct {
	Raw                     []byte
	RawTBSCertificate       []byte
	RawSubjectPublicKeyInfo []byte
	RawSubject              []byte
	RawIssuer               []byte

	Signature          []byte
	SignatureAlgorithm int

	PublicKeyAlgorithm int
	PublicKey          interface{}

	Version             int
	SerialNumber        []byte
	//Issuer              pkix.Name
	//Subject             pkix.Name
	NotBefore, NotAfter int64
	KeyUsage            int

	//Extensions         []pkix.Extension
	//ExtraExtensions    []pkix.Extension
	//ExtKeyUsage        []ExtKeyUsage
	//UnknownExtKeyUsage []asn1.ObjectIdentifier

	BasicConstraintsValid bool
	IsCA                  bool
	MaxPathLen            int

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            string
	IssuingCertificateURL string

	// Subject Alternate Name values
	DNSNames       string
	EmailAddresses string
	IPAddresses    []byte

	// Name constraints
	PermittedDNSDomainsCritical bool
	PermittedDNSDomains         []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	//PolicyIdentifiers []asn1.ObjectIdentifier
}

type CertChain struct {
	Id                        int64
	ConnectionID              int64
	Order                     int
	PeerCertificate           *Certificate
}

type VerifiedCertChain struct {
	Id                        int64
	ConnectionID              int64
	ChainIndex                int
	Order                     int
	VerifiedCertificate       *Certificate
}

func (r *ScanResult) GetRecord() *ScanRecord {
	var scan ScanRecord

	scan.TlsVersion = r.Smtp.Tls.Version
	scan.HandshakeComplete = r.Smtp.Tls.HandshakeComplete
	scan.DidResume = r.Smtp.Tls.DidResume
	scan.CipherSuite = r.Smtp.Tls.CipherSuite
	scan.NegotiatedProtocol = r.Smtp.Tls.NegotiatedProtocol
	scan.NegotiatedProtocolIsMutual = r.Smtp.Tls.NegotiatedProtocolIsMutual
	scan.ServerName = r.Smtp.Tls.ServerName

	scan.ServerName = r.Smtp.ServerName
	scan.Ext = r.Smtp.Ext
	scan.Auth = r.Smtp.Auth
	scan.LocalName = r.Smtp.LocalName
	scan.DidHello = r.Smtp.DidHello
	if r.Smtp.HelloError != nil {
		scan.HelloError = r.Smtp.HelloError.Error()
	}
	scan.ExtSTARTTLS = r.Smtp.ExtSTARTTLS
	scan.HasTls = r.Smtp.HasTls

	scan.Id = -1
	scan.Address = r.Address
	scan.Timestamp = r.Timestamp
	scan.ConnectionSuceeded = r.ConnectionSuceeded
	scan.Error = r.Error

	return &scan
}

func GetCertificateRecord(c *x509.Certificate) *Certificate {
	var cert Certificate

	cert.Raw = c.Raw
	cert.RawTBSCertificate = c.RawTBSCertificate
	cert.RawSubjectPublicKeyInfo = c.RawSubjectPublicKeyInfo
	cert.RawSubject = c.RawSubject
	cert.RawIssuer = c.RawIssuer

	cert.Signature = c.Signature
	cert.SignatureAlgorithm = int(c.SignatureAlgorithm)

	cert.PublicKeyAlgorithm = int(c.PublicKeyAlgorithm)
	cert.PublicKey = c.PublicKey
	cert.Version = c.Version
	cert.SerialNumber = c.SerialNumber.Bytes()

	//cert.Issuer = c.Issuer
	//cert.Subject = c.Subject
	cert.NotBefore = c.NotBefore.Unix()
	cert.NotAfter = c.NotAfter.Unix()
	cert.KeyUsage = int(c.KeyUsage)
	cert.BasicConstraintsValid = c.BasicConstraintsValid
	cert.IsCA = c.IsCA
	cert.MaxPathLen = c.MaxPathLen
	cert.SubjectKeyId = c.SubjectKeyId
	cert.AuthorityKeyId = c.AuthorityKeyId
	cert.OCSPServer = c.OCSPServer[0]
	cert.IssuingCertificateURL = c.IssuingCertificateURL[0]
	cert.DNSNames = c.DNSNames[0]
	cert.EmailAddresses = c.EmailAddresses[0]
	cert.IPAddresses, _= c.IPAddresses[0].MarshalText()
	cert.PermittedDNSDomainsCritical = c.PermittedDNSDomainsCritical
	cert.PermittedDNSDomains = c.PermittedDNSDomains
	cert.CRLDistributionPoints = c.CRLDistributionPoints
	return &cert
}

func (db *Database) InsertResult(r *ScanResult) error {
	scan := r.GetRecord()
	err := db.dbmap.Insert(scan)
	if err != nil {
		return err
	}

	/*
	for i, c := range r.Smtp.Tls.PeerCertificates {
		cert := GetCertificateRecord(c)
		chain := CertChain{-1, scan.Id, i, cert}
		err := db.dbmap.Insert(chain)
		if err != nil {
			return err
		}
	}
	for j, chain := range r.Smtp.Tls.VerifiedChains {
		for i, c := range chain {
			cert := GetCertificateRecord(c)
			chain := VerifiedCertChain{-1, scan.Id, j, i, cert}
			err := db.dbmap.Insert(chain)
			if err != nil {
				return err
			}
		}
	}
	*/
	return nil
}
