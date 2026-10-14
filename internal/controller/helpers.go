/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	warpgatev1alpha1 "github.com/thereisnotime/warpgate-operator/api/v1alpha1"
	"github.com/thereisnotime/warpgate-operator/internal/warpgate"
)

// getWarpgateClient builds a Warpgate API client by looking up the named WarpgateConnection
// CR and its referenced credentials Secret.
func getWarpgateClient(ctx context.Context, r client.Reader, namespace, connectionName string) (*warpgate.Client, error) {
	var conn warpgatev1alpha1.WarpgateConnection
	if err := r.Get(ctx, types.NamespacedName{Name: connectionName, Namespace: namespace}, &conn); err != nil {
		return nil, fmt.Errorf("getting WarpgateConnection %q: %w", connectionName, err)
	}

	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      conn.Spec.AuthSecretRef.Name,
		Namespace: namespace,
	}, &secret); err != nil {
		return nil, fmt.Errorf("getting auth secret %q: %w", conn.Spec.AuthSecretRef.Name, err)
	}

	tokenKey := conn.Spec.AuthSecretRef.TokenKey
	if tokenKey == "" {
		tokenKey = "token"
	}

	// Prefer token-based auth if the token key exists in the Secret.
	if token, ok := secret.Data[tokenKey]; ok && len(token) > 0 {
		return sharedClient(&conn, &secret, warpgate.Config{
			Host:               conn.Spec.Host,
			Token:              string(token),
			InsecureSkipVerify: conn.Spec.InsecureSkipVerify,
		}), nil
	}

	// Fall back to username/password auth.
	usernameKey := conn.Spec.AuthSecretRef.UsernameKey
	if usernameKey == "" {
		usernameKey = "username"
	}
	passwordKey := conn.Spec.AuthSecretRef.PasswordKey
	if passwordKey == "" {
		passwordKey = "password"
	}

	username, ok := secret.Data[usernameKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in auth secret %q", usernameKey, conn.Spec.AuthSecretRef.Name)
	}

	password, ok := secret.Data[passwordKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in auth secret %q", passwordKey, conn.Spec.AuthSecretRef.Name)
	}

	return sharedClient(&conn, &secret, warpgate.Config{
		Host:               conn.Spec.Host,
		Username:           string(username),
		Password:           string(password),
		InsecureSkipVerify: conn.Spec.InsecureSkipVerify,
	}), nil
}

// clients holds one Warpgate client per WarpgateConnection, so every reconcile shares its
// session instead of logging in again.
var clients = struct {
	sync.Mutex
	byConnection map[types.NamespacedName]cachedClient
}{byConnection: map[types.NamespacedName]cachedClient{}}

type cachedClient struct {
	config         warpgate.Config
	secretUID      types.UID
	secretRevision string
	client         *warpgate.Client
}

// sharedClient returns the connection's client, built again when its configuration or
// its credentials Secret changed.
func sharedClient(conn *warpgatev1alpha1.WarpgateConnection, secret *corev1.Secret, cfg warpgate.Config) *warpgate.Client {
	key := types.NamespacedName{Namespace: conn.Namespace, Name: conn.Name}
	clients.Lock()
	defer clients.Unlock()
	if c, ok := clients.byConnection[key]; ok && c.config == cfg &&
		c.secretUID == secret.UID && c.secretRevision == secret.ResourceVersion {
		return c.client
	}
	c := warpgate.NewClient(cfg)
	clients.byConnection[key] = cachedClient{config: cfg, secretUID: secret.UID, secretRevision: secret.ResourceVersion, client: c}
	return c
}
