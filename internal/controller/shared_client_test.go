package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	warpgatev1alpha1 "github.com/thereisnotime/warpgate-operator/api/v1alpha1"
	"github.com/thereisnotime/warpgate-operator/internal/warpgate"
)

func TestSharedClientIsReusedUntilSomethingChanges(t *testing.T) {
	conn := &warpgatev1alpha1.WarpgateConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "shared-client", Name: "wg"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{UID: "u1", ResourceVersion: "1"}}
	cfg := warpgate.Config{Host: "https://wg.example", Username: "op", Password: "pw"}

	first := sharedClient(conn, secret, cfg)
	if sharedClient(conn, secret, cfg) != first {
		t.Fatal("same connection and Secret: want the same client")
	}

	secret.ResourceVersion = "2"
	second := sharedClient(conn, secret, cfg)
	if second == first {
		t.Fatal("changed Secret: want a new client")
	}

	cfg.InsecureSkipVerify = true
	if sharedClient(conn, secret, cfg) == second {
		t.Fatal("changed configuration: want a new client")
	}

	other := &warpgatev1alpha1.WarpgateConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "shared-client", Name: "other"}}
	if sharedClient(other, secret, cfg) == sharedClient(conn, secret, cfg) {
		t.Fatal("different connections: want different clients")
	}

	recreated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{UID: "u2", ResourceVersion: "2"}}
	if sharedClient(conn, recreated, cfg) == sharedClient(conn, secret, cfg) {
		t.Fatal("recreated Secret with the same revision: want a new client")
	}
}
