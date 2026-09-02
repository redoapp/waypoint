//go:build integration

package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

const k3sImage = "rancher/k3s:v1.35.0-k3s1"

func TestIntegration_KubernetesProxy_K3sRBACAndExec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cluster, err := k3s.Run(ctx, k3sImage)
	if err != nil {
		t.Fatalf("start k3s: %v", err)
	}
	testcontainers.CleanupContainer(t, cluster)

	kubeconfig, err := cluster.GetKubeConfig(ctx)
	if err != nil {
		t.Fatalf("get k3s kubeconfig: %v", err)
	}
	adminConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		t.Fatalf("parse k3s kubeconfig: %v", err)
	}
	admin, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("create k3s admin client: %v", err)
	}

	token := configureK3sRBAC(t, ctx, admin)
	addr := startK3sProxy(t, adminConfig, token, k8sAuthResult(t, "waypoint:readonly"))
	proxyConfig := &rest.Config{
		Host: "http://" + addr,
		// Waypoint discards this token; client-go requires no auth for HTTP,
		// but setting one proves it cannot replace the proxy's apiserver token.
		BearerToken: "untrusted-client-token",
	}
	client, err := kubernetes.NewForConfig(proxyConfig)
	if err != nil {
		t.Fatalf("create proxy client: %v", err)
	}

	t.Run("list allowed by impersonated group", func(t *testing.T) {
		if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatalf("list pods through proxy: %v", err)
		}
	})

	t.Run("create denied by Kubernetes RBAC", func(t *testing.T) {
		_, err := client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "must-not-exist"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "nope", Image: "busybox"}},
			},
		}, metav1.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("create pod error = %v, want forbidden", err)
		}
	})

	t.Run("client impersonation cannot escalate", func(t *testing.T) {
		escalating := rest.CopyConfig(proxyConfig)
		escalating.Impersonate.UserName = "system:admin"
		escalating.Impersonate.Groups = []string{"system:masters"}
		escalatingClient, err := kubernetes.NewForConfig(escalating)
		if err != nil {
			t.Fatal(err)
		}
		_, err = escalatingClient.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "still-must-not-exist"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "nope", Image: "busybox"}},
			},
		}, metav1.CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("escalated create error = %v, want forbidden", err)
		}
	})

	t.Run("SPDY exec streams through proxy", func(t *testing.T) {
		waitForPodReady(t, ctx, admin, "exec-target")

		req := client.CoreV1().RESTClient().Post().
			Resource("pods").
			Name("exec-target").
			Namespace("default").
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: "shell",
				Command:   []string{"sh", "-c", "printf waypoint-exec-ok"},
				Stdout:    true,
				Stderr:    true,
			}, scheme.ParameterCodec)
		executor, err := remotecommand.NewSPDYExecutor(proxyConfig, http.MethodPost, req.URL())
		if err != nil {
			t.Fatalf("create SPDY executor: %v", err)
		}
		var stdout, stderr bytes.Buffer
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		}); err != nil {
			t.Fatalf("exec through proxy: %v (stderr: %s)", err, stderr.String())
		}
		if stdout.String() != "waypoint-exec-ok" {
			t.Fatalf("stdout = %q", stdout.String())
		}
	})
}

func configureK3sRBAC(t *testing.T, ctx context.Context, client kubernetes.Interface) string {
	t.Helper()
	const namespace = "default"
	if _, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "waypoint-proxy"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create waypoint service account: %v", err)
	}

	if _, err := client.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "waypoint-impersonator"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups", "serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create impersonator role: %v", err)
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "waypoint-impersonator"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "waypoint-impersonator",
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "waypoint-proxy",
			Namespace: namespace,
		}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("bind impersonator role: %v", err)
	}
	if _, err := client.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "waypoint-readonly"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create", "get"},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create readonly role: %v", err)
	}
	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "waypoint-readonly"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "waypoint-readonly",
		},
		Subjects: []rbacv1.Subject{{
			Kind:     "Group",
			Name:     "waypoint:readonly",
			APIGroup: "rbac.authorization.k8s.io",
		}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("bind readonly group: %v", err)
	}

	tokenRequest, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		"waypoint-proxy",
		&authenticationv1.TokenRequest{},
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatalf("create waypoint service account token: %v", err)
	}
	return tokenRequest.Status.Token
}

func startK3sProxy(t *testing.T, adminConfig *rest.Config, token string, authResult *auth.AuthResult) string {
	t.Helper()
	caPath := t.TempDir() + "/ca.crt"
	caData := adminConfig.CAData
	if len(caData) == 0 && adminConfig.CAFile != "" {
		var err error
		caData, err = os.ReadFile(adminConfig.CAFile)
		if err != nil {
			t.Fatalf("read k3s CA: %v", err)
		}
	}
	if len(caData) == 0 {
		t.Fatal("k3s kubeconfig contains no CA data")
	}
	if err := os.WriteFile(caPath, caData, 0o600); err != nil {
		t.Fatalf("write k3s CA: %v", err)
	}

	redisClient := testutil.RedisClient(t)
	m := metrics.Noop()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := restrict.NewTracker(restrict.NewRedisStore(redisClient, "k3stest:", m), m, logger)

	p := &KubernetesProxy{
		Backend:      adminConfig.Host,
		Name:         "eks-prod",
		Auth:         k8sTestAuthorizer{result: authResult},
		Tracker:      tracker,
		Metrics:      m,
		KubeConfig:   &config.KubernetesAdmin{Token: token, CAFile: caPath},
		BackendTLS:   true,
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}
	if err := p.Prepare(); err != nil {
		t.Fatalf("prepare Kubernetes proxy: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()
	return ln.Addr().String()
}

func waitForPodReady(t *testing.T, ctx context.Context, client kubernetes.Interface, name string) {
	t.Helper()
	if _, err := client.CoreV1().Pods("default").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "shell",
				Image:   "busybox:1.36",
				Command: []string{"sh", "-c", "sleep 300"},
			}},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create exec pod: %v", err)
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := client.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
		if err == nil && pod.Status.Phase == corev1.PodRunning {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for exec pod: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
