// Copyright 2016 Google Inc. All Rights Reserved.
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
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"encoding/pem"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"io"
)

const (
	apiHost                   = "http://127.0.0.1:8001"
	certificatesEndpoint      = "/apis/stable.k8s.psg.io/v1/namespaces/default/certificates"
	certificatesWatchEndpoint = "/apis/stable.k8s.psg.io/v1/namespaces/default/certificates?watch=true"
	secretsEndpoint           = "/api/v1/namespaces/default/secrets"
)

type CertificateEvent struct {
	Type   string      `json:"type"`
	Object Certificate `json:"object"`
}

type Certificate struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
	Spec       CertificateSpec   `json:"spec"`
}

type CertificateSpec struct {
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
}

type CertificateList struct {
	ApiVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
	Items      []Certificate     `json:"items"`
}

type Secret struct {
	Kind       string                 `json:"kind"`
	ApiVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
	Data       map[string][]byte      `json:"data"`
	Type       string                 `json:"type"`
}

type ACMECertData struct {
	DomainName string
	Cert       []byte
	PrivateKey []byte
}

type ACMEUserData struct {
	Email        string                     `json:"email"`
	Registration *acme.RegistrationResource `json:"registration"`
	Key          []byte                     `json:"key"`
}

type ACMECertDetails struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	AccountRef    string `json:"accountRef,omitempty"`
}

func (u *ACMEUserData) GetEmail() string {
	return u.Email
}

func (u *ACMEUserData) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u *ACMEUserData) GetPrivateKey() crypto.PrivateKey {
	pemBlock, _ := pem.Decode(u.Key)
	if pemBlock.Type != "RSA PRIVATE KEY" {
		log.Printf("Invalid PEM user key: Expected RSA PRIVATE KEY, got %v", pemBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Printf("Error while parsing private key: %v", err)
	}

	return privateKey
}

func (c *ACMECertData) ToSecret(prefix string) (*Secret, error) {
	metadata := make(map[string]interface{})
	metadata["name"] = prefix + c.DomainName
	metadata["labels"] = map[string]string{"domain": c.DomainName}

	data := make(map[string][]byte)
	data["tls.crt"] = c.Cert
	data["tls.key"] = c.PrivateKey

	return &Secret{
		ApiVersion: "v1",
		Data:       data,
		Kind:       "Secret",
		Metadata:   metadata,
		Type:       "kubernetes.io/tls",
	}, nil
}

func NewACMECertDataFromSecret(s *Secret) (ACMECertData, error) {
	var acmeCertData ACMECertData
	var ok bool

	labels, ok := s.Metadata["labels"].(map[string]interface{})
	if !ok {
		return acmeCertData, errors.Errorf("Could not cast labels, expected map[string]interface{}, got %T", s.Metadata["labels"])
	}

	acmeCertData.DomainName, ok = labels["domain"].(string)
	if !ok {
		return acmeCertData, errors.Errorf("Could not find metadata domain in secret %v", s.Metadata["name"])
	}

	acmeCertData.Cert, ok = s.Data["tls.crt"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.crt in secret %v", s.Metadata["name"])
	}

	acmeCertData.PrivateKey, ok = s.Data["tls.key"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.key in secret %v", s.Metadata["name"])
	}

	return acmeCertData, nil
}

func NewACMECertDetailsFromResource(certRes acme.CertificateResource) ACMECertDetails {
	return ACMECertDetails{
		Domain:        certRes.Domain,
		CertURL:       certRes.CertURL,
		CertStableURL: certRes.CertStableURL,
		AccountRef:    certRes.AccountRef,
	}
}

func (certDetails *ACMECertDetails) ToCertResource() acme.CertificateResource {
	return acme.CertificateResource{
		Domain:        certDetails.Domain,
		CertURL:       certDetails.CertURL,
		CertStableURL: certDetails.CertStableURL,
		AccountRef:    certDetails.AccountRef,
	}
}

func getSecret(key string) (*Secret, error) {
	// Run the http request
	url := apiHost + secretsEndpoint + "/" + key
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrapf(err, "Error while running http request on url: %v", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Unexpected http status response while fetching secret on url %q: %v", url, resp.Status)
	}

	// Deserialize the secret
	var secret Secret
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&secret)
	if err != nil {
		return nil, errors.Wrap(err, "Error while deserializing secret")
	}

	return &secret, nil
}

func saveSecret(secret *Secret, isUpdate bool) error {
	if secret.Metadata["name"] == "" {
		return errors.New("Secret name must be specified in metadata")
	}

	// Serialize the secret
	buffer := new(bytes.Buffer)
	err := json.NewEncoder(buffer).Encode(secret)
	if err != nil {
		return errors.Wrapf(err, "Error while encoding secret: %v", err)
	}

	// Determine http method and url
	var url string
	var method string
	if isUpdate {
		url = apiHost + secretsEndpoint + "/" + secret.Metadata["name"].(string)
		method = "PUT"
	} else {
		url = apiHost + secretsEndpoint
		method = "POST"
	}

	req, err := http.NewRequest(method, url, buffer)
	if err != nil {
		return errors.Wrapf(err, "Error while creating http request on url: %v", url)
	}
	req.Header.Add("Content-Type", "application/json")

	// Actually do the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Error while running http request on url: %v", url)
	}
	defer resp.Body.Close()

	if isUpdate && resp.StatusCode != 200 {
		return errors.Errorf("Non OK status while updating secret: %v", resp.Status)
	} else if !isUpdate && resp.StatusCode != 201 {
		return errors.Errorf("Non Created status while creating secret: %v", resp.Status)
	}

	return nil
}

func deleteSecret(key string) error {
	// Create DELETE request
	url := apiHost + secretsEndpoint + "/" + key
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errors.Wrapf(err, "Error while creating http request for url: %v", url)
	}

	// Actually do the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "Error while running http request on url: %v", url)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Deleting %s secret failed: %s", key, resp.Status)
	}

	return nil
}

func getCertificates() ([]Certificate, error) {
	var resp *http.Response
	var err error

	for {
		resp, err = http.Get(apiHost + certificatesEndpoint)
		if err != nil {
			log.Printf("Error while retrieving certificate: %v. Retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	var certList CertificateList
	err = json.NewDecoder(resp.Body).Decode(&certList)
	if err != nil {
		return nil, err
	}

	return certList.Items, nil
}

func monitorCertificateEvents() (<-chan CertificateEvent, <-chan error) {
	events := make(chan CertificateEvent)
	errc := make(chan error, 1)
	go func() {
		for {
			resp, err := http.Get(apiHost + certificatesWatchEndpoint)
			if err != nil {
				errc <- err
				time.Sleep(5 * time.Second)
				continue
			}
			if resp.StatusCode != 200 {
				errc <- errors.New("Invalid status code: " + resp.Status)
				time.Sleep(5 * time.Second)
				continue
			}

			decoder := json.NewDecoder(resp.Body)
			for {
				var event CertificateEvent
				err = decoder.Decode(&event)
				if err != nil && err != io.EOF {
					errc <- err
					break
				}
				events <- event
			}
		}
	}()

	return events, errc
}
