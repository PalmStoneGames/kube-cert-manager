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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/runtime/serializer"
	"k8s.io/client-go/pkg/watch/versioned"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/boltdb/bolt"
)

type listFlag []string

func (lf *listFlag) String() string {
	return strings.Join([]string(*lf), ",")
}

func (lf *listFlag) Set(s string) error {
	if len(s) == 0 {
		*lf = []string{}
		return nil
	}
	*lf = strings.Split(s, ",")
	return nil
}

func main() {
	// Parse command line
	var (
		kubeconfig       string
		acmeURL          string
		syncInterval     int
		certSecretPrefix string
		dataDir          string
		certNamespace    string
		tagPrefix        string
		namespaces       []string
		class            string
		defaultProvider  string
		defaultEmail     string
		renewBeforeDays  int
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "The kubeconfig to use; if empty the in-cluster config will be used")
	flag.StringVar(&acmeURL, "acme-url", "", "The URL to the acme directory to use")
	flag.StringVar(&certSecretPrefix, "cert-secret-prefix", "", "The prefix to use for certificate secrets")
	flag.IntVar(&syncInterval, "sync-interval", 30, "Sync interval in seconds")
	flag.StringVar(&dataDir, "data-dir", "/var/lib/cert-manager", "Data directory path")
	flag.StringVar(&certNamespace, "cert-namespace", "stable.k8s.psg.io", "Namespace for the Certificate Third Party Resource")
	flag.StringVar(&tagPrefix, "tag-prefix", "stable.k8s.psg.io/kcm.", "Prefix added to labels and annotations")
	flag.Var((*listFlag)(&namespaces), "namespaces", "Comma-separated list of namespaces to monitor. The empty list means all namespaces")
	flag.StringVar(&class, "class", "default", "Class label for resources managed by this certificate manager")
	flag.StringVar(&defaultProvider, "default-provider", "", "Default handler to handle ACME challenges")
	flag.StringVar(&defaultEmail, "default-email", "", "Default email address for ACME registrations")
	flag.IntVar(&renewBeforeDays, "renew-before-days", 7, "Renew certificates before this number of days until expiry")
	flag.Parse()

	if acmeURL == "" {
		log.Fatal("The acme-url command line parameter must be specified")
	}

	// Initialize bolt
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("Error while creating %v directory: %v", dataDir, err)
	}

	dbPath := path.Join(dataDir, "data.db")
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatalf("Error while creating bolt database file at %v: %v", dbPath, err)
	}

	for _, bucketName := range []string{"user-info", "cert-details", "domain-altnames"} {
		err = db.Update(func(tx *bolt.Tx) error {
			_, err = tx.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return fmt.Errorf("create bucket: %s", err)
			}
			return nil
		})

		if err != nil {
			log.Fatalf("Error while creating bolt bucket %v: %v", bucketName, err)
		}
	}

	log.Println("Starting Kubernetes Certificate Controller...")
	log.Println("All errors logs are forwarded to k8s events. To watch the logs use 'kubectl get events -w -n mynamespace'")

	var k8sConfig *rest.Config
	if kubeconfig == "" {
		k8sConfig, err = rest.InClusterConfig()
	} else {
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		log.Fatalf("Error trying to configure k8s client: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Error trying to to create k8s client: %v", err)
	}

	groupVersion := unversioned.GroupVersion{
		Group:   "stable.k8s.psg.io",
		Version: "v1",
	}
	// Create a client for the certificate TPR too
	schemeBuilder := runtime.NewSchemeBuilder(
		func(scheme *runtime.Scheme) error {
			scheme.AddKnownTypes(
				groupVersion,
				&Certificate{},
				&CertificateList{},
				&api.ListOptions{},
				&api.DeleteOptions{},
			)
			versioned.AddToGroupVersion(scheme, groupVersion)
			return nil
		})
	if err := schemeBuilder.AddToScheme(api.Scheme); err != nil {
		log.Fatalf("error setting up certificate scheme: %v", err)
	}

	tprConfig := *k8sConfig
	tprConfig.GroupVersion = &groupVersion
	tprConfig.APIPath = "/apis"
	tprConfig.ContentType = runtime.ContentTypeJSON
	tprConfig.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: api.Codecs}

	certClient, err := rest.RESTClientFor(&tprConfig)
	if err != nil {
		log.Fatalf("error creating TPR Certificate client: %v", err)
	}

	// Create the processor
	p := NewCertProcessor(k8sClient, certClient, acmeURL, certSecretPrefix, certNamespace, tagPrefix, namespaces, class, defaultProvider, defaultEmail, db, renewBeforeDays)

	// Asynchronously start watching and refreshing certs
	wg := sync.WaitGroup{}
	doneChan := make(chan struct{})

	if len(p.namespaces) == 0 {
		wg.Add(1)
		go p.watchKubernetesEvents(
			v1.NamespaceAll,
			p.getLabelSelector(),
			&wg,
			doneChan)
	} else {
		for _, namespace := range p.namespaces {
			wg.Add(1)
			go p.watchKubernetesEvents(
				namespace,
				p.getLabelSelector(),
				&wg,
				doneChan,
			)
		}
	}
	wg.Add(1)
	go p.maintenance(time.Second*time.Duration(syncInterval), &wg, doneChan)

	log.Println("Kubernetes Certificate Controller started successfully.")

	// Listen for shutdown signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("Shutdown signal received, exiting...")
	close(doneChan)
	wg.Wait()
	return
}
