// Copyright 2016 Google Inc. All Rights Reserved.
// Copyright 2016 Palm Stone Games, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"sync"
	"time"
	"encoding/json"

	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/googlecloud"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/ovh"
	"github.com/xenolf/lego/providers/dns/pdns"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/vultr"
)

type CertProcessor struct {
	certSecretPrefix string
	acmeURL          string
	db               *bolt.DB
	Lock             sync.Mutex
	HTTPLock         sync.Mutex
	TLSLock          sync.Mutex
}

func NewCertProcessor(acmeURL string, certSecretPrefix string, db *bolt.DB) *CertProcessor {
	return &CertProcessor{acmeURL: acmeURL,
		certSecretPrefix: certSecretPrefix,
		db:               db,
	}
}

func (p *CertProcessor) newACMEClient(acmeUser acme.User, provider string) (*acme.Client, *sync.Mutex, error) {
	acmeClient, err := acme.NewClient(p.acmeURL, acmeUser, acme.RSA2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error while generating acme client")
	}

	initDNSProvider := func(p acme.ChallengeProvider, err error) (*acme.Client, *sync.Mutex, error) {
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Error while initializing provider %v", provider)
		}

		if err := acmeClient.SetChallengeProvider(acme.DNS01, p); err != nil {
			return nil, nil, errors.Wrap(err, "Error while setting cloudflare challenge provider")
		}

		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
		return acmeClient, nil, nil
	}

	switch provider {
	case "http":
		acmeClient.SetHTTPAddress("8080")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.DNS01, acme.TLSSNI01})
		return acmeClient, &p.HTTPLock, nil
	case "tls":
		acmeClient.SetTLSAddress("8081")
		acmeClient.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.DNS01})
		return acmeClient, &p.TLSLock, nil
	case "cloudflare":
		return initDNSProvider(cloudflare.NewDNSProvider())
	case "digitalocean":
		return initDNSProvider(digitalocean.NewDNSProvider())
	case "dnsimple":
		return initDNSProvider(dnsimple.NewDNSProvider())
	case "dnsmadeeasy":
		return initDNSProvider(dnsmadeeasy.NewDNSProvider())
	case "dyn":
		return initDNSProvider(dyn.NewDNSProvider())
	case "gandi":
		return initDNSProvider(gandi.NewDNSProvider())
	case "googlecloud":
		return initDNSProvider(googlecloud.NewDNSProvider())
	case "namecheap":
		return initDNSProvider(namecheap.NewDNSProvider())
	case "ovh":
		return initDNSProvider(ovh.NewDNSProvider())
	case "pdns":
		return initDNSProvider(pdns.NewDNSProvider())
	case "rfc2136":
		return initDNSProvider(rfc2136.NewDNSProvider())
	case "route53":
		return initDNSProvider(route53.NewDNSProvider())
	case "vultr":
		return initDNSProvider(vultr.NewDNSProvider())
	default:
		return nil, nil, errors.Errorf("Unknown provider %v", provider)
	}
}

func (p *CertProcessor) syncCertificates(verbose bool) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()

	certificates, err := getCertificates()
	if err != nil {
		return errors.Wrap(err, "Error while fetching certificate list")
	}

	var wg sync.WaitGroup
	for _, cert := range certificates {
		wg.Add(1)
		go func(cert Certificate) {
			defer wg.Done()
			err := p.processCertificate(&cert.Spec)
			if err != nil {
				log.Printf("Error while processing certificate during sync: %v", err)
			}
		}(cert)
	}
	wg.Wait()
	return nil
}

func (p *CertProcessor) watchKubernetesEvents(wg *sync.WaitGroup, doneChan <-chan struct{}) {
	events, watchErrs := monitorCertificateEvents()
	go func() {
		for {
			select {
			case event := <-events:
				err := p.processCertificateEvent(event)
				if err != nil {
					log.Printf("Error while processing certificate event: %v", err)
				}
			case err := <-watchErrs:
				log.Printf("Error while watching kubernetes events: %v", err)
			case <-doneChan:
				wg.Done()
				log.Println("Stopped certificate event watcher.")
				return
			}
		}
	}()
}

func (p *CertProcessor) refreshCertificates(syncInterval time.Duration, wg *sync.WaitGroup, doneChan <-chan struct{}) {
	go func() {
		for {
			select {
			case <-time.After(syncInterval):
				err := p.syncCertificates(false)
				if err != nil {
					log.Printf("Error while synchronizing certificates during refresh: %v", err)
				}
			case <-doneChan:
				wg.Done()
				log.Println("Stopped refresh loop.")
				return
			}
		}
	}()
}

func (p *CertProcessor) processCertificateEvent(c CertificateEvent) error {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	switch {
	case c.Type == "ADDED":
		return p.processCertificate(&c.Object.Spec)
	case c.Type == "DELETED":
		return p.deleteCertificate(&c.Object.Spec)
	}
	return nil
}

func (p *CertProcessor) processCertificate(certSpec *CertificateSpec) error {
	var (
		acmeUserInfo    ACMEUserData
		acmeCertDetails ACMECertDetails
		acmeCert        ACMECertData
		acmeClient      *acme.Client
		acmeClientMutex *sync.Mutex
	)

	// Fetch current certificate data from k8s
	s, err := getSecret(p.certSecretPrefix + certSpec.Domain)
	if err != nil {
		return errors.Wrapf(err, "Error while fetching certificate acme data for domain %v", certSpec.Domain)
	}

	// If a cert exists, check its expiry
	if s != nil {
		acmeCert, err = NewACMECertDataFromSecret(s)
		if err != nil {
			return errors.Wrapf(err, "Error while decoding acme certificate from secret for existing domain %v", certSpec.Domain)
		}

		// Decode cert
		pemBlock, _ := pem.Decode(acmeCert.Cert)
		parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return errors.Wrapf(err, "Error while decoding x509 encoded certificate for existing domain %v", certSpec.Domain)
		}

		// If certificate expires in more than a week, don't renew
		if parsedCert.NotAfter.After(time.Now().Add(time.Hour * 24 * 7)) {
			return nil
		}

		log.Printf("[%v] Expiry for cert is in less than a week (%v), attempting renewal", certSpec.Domain, parsedCert.NotAfter.String())
	}

	// Fetch acme user data and cert details from bolt
	var userInfoRaw, certDetailsRaw []byte
	err = p.db.View(func(tx *bolt.Tx) error {
		userInfoRaw = tx.Bucket([]byte("user-info")).Get([]byte(certSpec.Domain))
		certDetailsRaw = tx.Bucket([]byte("cert-details")).Get([]byte(certSpec.Domain))
		return nil
	})

	if err != nil {
		return errors.Wrapf(err, "Error while running bolt view transaction for domain %v", certSpec.Domain)
	}

	// Handle user information
	if userInfoRaw != nil { // Use existing user
		if err := json.Unmarshal(userInfoRaw, &acmeUserInfo); err != nil {
			return errors.Wrapf(err, "Error while unmarshalling user info for %v", certSpec.Domain)
		}

		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, certSpec.Provider)
		if err != nil {
			return errors.Wrapf(err, "Error while creating ACME client for %v", certSpec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Lock()
		}
	} else { // Generate a new ACME user
		userKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return errors.Wrapf(err, "Error while generating rsa key for new user for domain %v", certSpec.Domain)
		}

		acmeUserInfo.Email = certSpec.Email
		acmeUserInfo.Key = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(userKey),
		})

		acmeClient, acmeClientMutex, err = p.newACMEClient(&acmeUserInfo, certSpec.Provider)
		if err != nil {
			return errors.Wrapf(err, "Error while creating ACME client for %v", certSpec.Domain)
		}

		// Some acme providers require locking, if the mutex is specified, lock it
		if acmeClientMutex != nil {
			acmeClientMutex.Lock()
			defer acmeClientMutex.Lock()
		}

		// Register
		acmeUserInfo.Registration, err = acmeClient.Register()
		if err != nil {
			return errors.Wrapf(err, "Error while registering user for new domain %v", certSpec.Domain)
		}

		// Agree to TOS
		if err := acmeClient.AgreeToTOS(); err != nil {
			return errors.Wrapf(err, "Error while agreeing to acme TOS for new domain %v", certSpec.Domain)
		}
	}

	// If we have cert details stored, do a renewal, otherwise, obtain from scratch
	if certDetailsRaw == nil || acmeCert.DomainName == "" {
		acmeCert.DomainName = certSpec.Domain

		// Obtain a cert
		certRes, errs := acmeClient.ObtainCertificate([]string{certSpec.Domain}, true, nil)
		if errs[certSpec.Domain] != nil {
			return errors.Wrapf(errs[certSpec.Domain], "Error while obtaining certificate for new domain %v", certSpec.Domain)
		}

		// fill in data
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	} else {
		if err := json.Unmarshal(certDetailsRaw, &acmeCertDetails); err != nil {
			return errors.Wrapf(err, "Error while unmarshalling cert details for existing domain %v", certSpec.Domain)
		}

		// Fill in cert resource
		certRes := acmeCertDetails.ToCertResource()
		certRes.Certificate = acmeCert.Cert
		certRes.PrivateKey = acmeCert.PrivateKey

		certRes, err = acmeClient.RenewCertificate(certRes, true)
		if err != nil {
			return errors.Wrapf(err, "Error while renewing certificate for existing domain %v", certSpec.Domain)
		}

		// Fill in details
		acmeCert.Cert = certRes.Certificate
		acmeCert.PrivateKey = certRes.PrivateKey
		acmeCertDetails = NewACMECertDetailsFromResource(certRes)
	}

	// Serialize acmeCertDetails and acmeUserInfo
	certDetailsRaw, err = json.Marshal(&acmeCertDetails)
	if err != nil {
		return errors.Wrapf(err, "Error while marshalling cert details for domain %v", certSpec.Domain)
	}

	userInfoRaw, err = json.Marshal(&acmeUserInfo)
	if err != nil {
		return errors.Wrapf(err, "Error while marshalling user info for domain %v", certSpec.Domain)
	}

	// Save cert details and user info to bolt
	err = p.db.Update(func(tx *bolt.Tx) error {
		key := []byte(certSpec.Domain)
		tx.Bucket([]byte("user-info")).Put(key, userInfoRaw)
		tx.Bucket([]byte("cert-details")).Put(key, certDetailsRaw)
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "Error while saving data to bolt for domain %v", certSpec.Domain)
	}

	// Convert cert data to k8s secret
	isUpdate := s != nil
	s, err = acmeCert.ToSecret(p.certSecretPrefix)
	if err != nil {
		return errors.Wrapf(err, "Error while creating secret for ACME certificate for domain %v", certSpec.Domain)
	}

	// Save the k8s secret
	if err := saveSecret(s, isUpdate); err != nil {
		return errors.Wrapf(err, "Error while saving secret for domain %v", certSpec.Domain)
	}

	return nil
}

func (p *CertProcessor) deleteCertificate(certSpec *CertificateSpec) error {
	return deleteSecret(p.certSecretPrefix + certSpec.Domain)
}
