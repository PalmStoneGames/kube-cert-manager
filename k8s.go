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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
)

const (
	apiHost            = "http://127.0.0.1:8001"
	certEndpoint       = "/apis/stable.k8s.psg.io/v1/namespaces/%s/certificates"
	certEndpointAll    = "/apis/stable.k8s.psg.io/v1/certificates"
	ingressEndpoint    = "/apis/extensions/v1beta1/namespaces/%s/ingresses"
	ingressEndpointAll = "/apis/extensions/v1beta1/ingresses"
	secretsEndpoint    = "/api/v1/namespaces/%s/secrets"
	secretsEndpointAll = "/api/v1/secrets"
	eventsEndpoint     = "/api/v1/namespaces/%s/events"

	annotationNamespace = "stable.k8s.psg.io/kcm"
)

type Metadata struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	UID             string            `json:"uid,omitempty"`
}

type WatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

type CertificateEvent struct {
	Type   string      `json:"type"`
	Object Certificate `json:"object"`
}

type Certificate struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       CertificateSpec `json:"spec"`
}

type CertificateSpec struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Email      string `json:"email"`
	SecretName string `json:"secretName"`
}

type CertificateList struct {
	APIVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   Metadata      `json:"metadata"`
	Items      []Certificate `json:"items"`
}

type Secret struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Metadata   Metadata          `json:"metadata"`
	Data       map[string][]byte `json:"data"`
	Type       string            `json:"type"`
}

type SecretList struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Items      []Secret `json:"items"`
}

type ACMECertData struct {
	DomainName string
	Cert       []byte
	PrivateKey []byte
}

type IngressEvent struct {
	Type   string  `json:"type"`
	Object Ingress `json:"object"`
}

type Ingress struct {
	Metadata Metadata    `json:"metadata"`
	Spec     IngressSpec `json:"spec"`
}

type IngressSpec struct {
	TLS []IngressTLS `json:"tls"`
}

type IngressTLS struct {
	Hosts      []string `json:"hosts"`
	SecretName string   `json:"secretName"`
}

type IngressList struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   Metadata  `json:"metadata"`
	Items      []Ingress `json:"items"`
}

type Event struct {
	Kind           string          `json:"kind"`
	APIVersion     string          `json:"apiVersion"`
	Metadata       Metadata        `json:"metadata"`
	InvolvedObject ObjectReference `json:"involvedObject"`
	Reason         string          `json:"reason"`
	Message        string          `json:"message"`
	Source         EventSource     `json:"source"`
	FirstTimestamp string          `json:"firstTimestamp,omitempty"`
	LastTimestamp  string          `json:"lastTimestamp,omitempty"`
	Count          int             `json:"count,omitempty"`
	Type           string          `json:"type"`
}

type ObjectReference struct {
	Kind            string `json:"kind,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	UID             string `json:"uid,omitempty"`
	APIVersion      string `json:"apiVersion,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	FieldPath       string `json:"fieldPath,omitempty"`
}

type EventSource struct {
	Component string `json:"component,omitempty"`
	Host      string `json:"host,omitempty"`
}

func ingressReference(ing Ingress, path string) ObjectReference {
	return ObjectReference{
		Kind:            "Ingress",
		Namespace:       ing.Metadata.Namespace,
		Name:            ing.Metadata.Name,
		UID:             ing.Metadata.UID,
		ResourceVersion: ing.Metadata.ResourceVersion,
		FieldPath:       path,
	}
}

func createEvent(ev Event) {
	now := time.Now()
	ev.Metadata.Name = fmt.Sprintf("%s.%x", ev.InvolvedObject.Name, now.UnixNano())
	if ev.Kind == "" {
		ev.Kind = "Event"
	}
	if ev.APIVersion == "" {
		ev.APIVersion = "v1"
	}
	if ev.FirstTimestamp == "" {
		ev.FirstTimestamp = now.Format(time.RFC3339Nano)
	}
	if ev.LastTimestamp == "" {
		ev.LastTimestamp = now.Format(time.RFC3339Nano)
	}
	if ev.Count == 0 {
		ev.Count = 1
	}
	b, err := json.Marshal(ev)
	if err != nil {
		log.Println("internal error:", err)
		return
	}
	resp, err := http.Post(apiHost+namespacedEndpoint(eventsEndpoint, ev.Metadata.Namespace), "application/json", bytes.NewReader(b))
	if err != nil {
		log.Println("internal error:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Println("unexpected HTTP status code while creating event:", resp.StatusCode)
	}
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

func (c *ACMECertData) ToSecret() *Secret {
	var metadata Metadata
	metadata.Labels = map[string]string{"domain": c.DomainName}
	metadata.Annotations = map[string]string{
		annotationNamespace: "true",
	}

	data := make(map[string][]byte)
	data["tls.crt"] = c.Cert
	data["tls.key"] = c.PrivateKey

	return &Secret{
		APIVersion: "v1",
		Data:       data,
		Kind:       "Secret",
		Metadata:   metadata,
		Type:       "kubernetes.io/tls",
	}
}

func NewACMECertDataFromSecret(s *Secret) (ACMECertData, error) {
	var acmeCertData ACMECertData
	var ok bool

	acmeCertData.DomainName = s.Metadata.Labels["domain"]
	acmeCertData.Cert, ok = s.Data["tls.crt"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.crt in secret %v", s.Metadata.Name)
	}
	acmeCertData.PrivateKey, ok = s.Data["tls.key"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.key in secret %v", s.Metadata.Name)
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

func getSecret(namespace string, key string) (*Secret, error) {
	// Run the http request
	url := apiHost + namespacedEndpoint(secretsEndpoint, namespace) + "/" + key
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

func saveSecret(namespace string, secret *Secret, isUpdate bool) error {
	if secret.Metadata.Name == "" {
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
		url = apiHost + namespacedEndpoint(secretsEndpoint, namespace) + "/" + secret.Metadata.Name
		method = "PUT"
	} else {
		url = apiHost + namespacedEndpoint(secretsEndpoint, namespace)
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

func deleteSecret(namespace string, key string) error {
	// Create DELETE request
	url := apiHost + namespacedEndpoint(secretsEndpoint, namespace) + "/" + key
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

func getSecrets(endpoint string) ([]Secret, error) {
	var resp *http.Response
	var err error

	for {
		resp, err = http.Get(apiHost + endpoint)
		if err != nil {
			log.Printf("Error while retrieving certificate: %v. Retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	var secretList SecretList
	err = json.NewDecoder(resp.Body).Decode(&secretList)
	if err != nil {
		return nil, err
	}

	return secretList.Items, nil
}

func getCertificates(endpoint string) ([]Certificate, error) {
	var resp *http.Response
	var err error

	for {
		resp, err = http.Get(apiHost + endpoint)
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

func getIngresses(endpoint string) ([]Ingress, error) {
	var resp *http.Response
	var err error

	for {
		resp, err = http.Get(apiHost + endpoint)
		if err != nil {
			log.Printf("Error while retrieving ingress: %v. Retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	var ingressList IngressList
	err = json.NewDecoder(resp.Body).Decode(&ingressList)
	if err != nil {
		return nil, err
	}

	return ingressList.Items, nil
}

func monitorEvents(endpoint string) (<-chan WatchEvent, <-chan error) {
	events := make(chan WatchEvent)
	errc := make(chan error, 1)
	go func() {
		resourceVersion := "0"
		for {
			resp, err := http.Get(apiHost + endpoint + "?watch=true&resourceVersion=" + resourceVersion)
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
				var event WatchEvent
				err = decoder.Decode(&event)
				if err != nil {
					if err != io.EOF {
						errc <- err
					}
					break
				}
				var header struct {
					Metadata struct {
						ResourceVersion string `json:"resourceVersion"`
					} `json:"metadata"`
				}
				if err := json.Unmarshal([]byte(event.Object), &header); err != nil {
					errc <- err
					break
				}
				resourceVersion = header.Metadata.ResourceVersion
				events <- event
			}
		}
	}()

	return events, errc
}

func monitorCertificateEvents(endpoint string) (<-chan CertificateEvent, <-chan error) {
	rawEvents, rawErrc := monitorEvents(endpoint)
	events := make(chan CertificateEvent)
	errc := make(chan error, 1)
	go func() {
		for {
			select {
			case ev := <-rawEvents:
				var event CertificateEvent
				event.Type = ev.Type
				err := json.Unmarshal([]byte(ev.Object), &event.Object)
				if err != nil {
					errc <- err
					continue
				}
				events <- event
			case err := <-rawErrc:
				errc <- err
			}
		}
	}()

	return events, errc
}

func monitorIngressEvents(endpoint string) (<-chan IngressEvent, <-chan error) {
	rawEvents, rawErrc := monitorEvents(endpoint)
	events := make(chan IngressEvent)
	errc := make(chan error, 1)
	go func() {
		for {
			select {
			case ev := <-rawEvents:
				var event IngressEvent
				event.Type = ev.Type
				err := json.Unmarshal([]byte(ev.Object), &event.Object)
				if err != nil {
					errc <- err
					continue
				}
				events <- event
			case err := <-rawErrc:
				errc <- err
			}
		}
	}()

	return events, errc
}

func namespacedEndpoint(endpoint string, namespace string) string {
	return fmt.Sprintf(endpoint, namespace)
}
