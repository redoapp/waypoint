package provision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
)

// OpenSearchRoleSpec is the OpenSearch Security role API payload.
type OpenSearchRoleSpec struct {
	ClusterPermissions []string                         `json:"cluster_permissions,omitempty"`
	IndexPermissions   []OpenSearchIndexPermissionSpec  `json:"index_permissions,omitempty"`
	TenantPermissions  []OpenSearchTenantPermissionSpec `json:"tenant_permissions,omitempty"`
}

// OpenSearchIndexPermissionSpec is one index permission block in an
// OpenSearch Security role.
type OpenSearchIndexPermissionSpec struct {
	IndexPatterns  []string `json:"index_patterns"`
	DLS            string   `json:"dls,omitempty"`
	FLS            []string `json:"fls,omitempty"`
	MaskedFields   []string `json:"masked_fields,omitempty"`
	AllowedActions []string `json:"allowed_actions"`
}

// OpenSearchTenantPermissionSpec is one tenant permission block in an
// OpenSearch Security role.
type OpenSearchTenantPermissionSpec struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// OpenSearchPresetNames lists all recognized OpenSearch preset names.
var OpenSearchPresetNames = []string{"readonly", "readwrite", "admin"}

// OpenSearchProvisioner manages dynamic OpenSearch internal users and roles
// through the Security plugin REST API.
type OpenSearchProvisioner struct {
	adminURL    *url.URL
	adminUser   string
	adminPass   string
	userPrefix  string
	peerService string
	store       *restrict.RedisStore
	logger      *slog.Logger
	httpClient  *http.Client
	auth        OpenSearchAuthenticator

	credCache sync.Map // map[string]*cachedCredential
}

// OpenSearchProvisionerOption customizes an OpenSearchProvisioner at construction.
type OpenSearchProvisionerOption func(*OpenSearchProvisioner)

// WithOpenSearchAuthenticator overrides the default Basic-auth backend
// authentication (e.g. with AWS SigV4 signing for Amazon OpenSearch Service).
func WithOpenSearchAuthenticator(a OpenSearchAuthenticator) OpenSearchProvisionerOption {
	return func(p *OpenSearchProvisioner) {
		if a != nil {
			p.auth = a
		}
	}
}

// NewOpenSearchProvisioner creates a new OpenSearch provisioner. By default it
// authenticates to the Security REST API with Basic auth using the supplied
// admin credentials; pass WithOpenSearchAuthenticator to sign requests instead.
func NewOpenSearchProvisioner(adminUser, adminPassword, backend, userPrefix, peerService string, backendTLS bool, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), opts ...OpenSearchProvisionerOption) *OpenSearchProvisioner {
	if userPrefix == "" {
		userPrefix = "wp_"
	}
	scheme := "http"
	if backendTLS {
		scheme = "https"
	}
	baseURL := &url.URL{
		Scheme: scheme,
		Host:   backend,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if dialFunc != nil {
		transport.DialContext = dialFunc
	}
	if backendTLS {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
		if host, _, err := net.SplitHostPort(backend); err == nil {
			tlsConfig.ServerName = host
		}
		transport.TLSClientConfig = tlsConfig
	}

	p := &OpenSearchProvisioner{
		adminURL:    baseURL,
		adminUser:   adminUser,
		adminPass:   adminPassword,
		userPrefix:  userPrefix,
		peerService: peerService,
		store:       store,
		logger:      logger,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		auth: basicAuthenticator{user: adminUser, pass: adminPassword},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ExpandOpenSearchPermissions expands ACL presets and raw grants into a
// canonical OpenSearch role spec.
func ExpandOpenSearchPermissions(perms *auth.OpenSearchCap) (OpenSearchRoleSpec, error) {
	if perms == nil {
		return OpenSearchRoleSpec{}, nil
	}

	spec := OpenSearchRoleSpec{
		ClusterPermissions: append([]string{}, perms.ClusterPermissions...),
	}

	for pattern, indexPerms := range perms.Indices {
		clusterFromPresets, actions, err := expandOpenSearchPresetActions(indexPerms.Permissions)
		if err != nil {
			return OpenSearchRoleSpec{}, err
		}
		spec.ClusterPermissions = append(spec.ClusterPermissions, clusterFromPresets...)
		actions = append(actions, indexPerms.AllowedActions...)
		spec.IndexPermissions = append(spec.IndexPermissions, OpenSearchIndexPermissionSpec{
			IndexPatterns:  []string{pattern},
			DLS:            indexPerms.DLS,
			FLS:            append([]string{}, indexPerms.FLS...),
			MaskedFields:   append([]string{}, indexPerms.MaskedFields...),
			AllowedActions: actions,
		})
	}

	for pattern, tenantPerms := range perms.Tenants {
		spec.TenantPermissions = append(spec.TenantPermissions, OpenSearchTenantPermissionSpec{
			TenantPatterns: []string{pattern},
			AllowedActions: append([]string{}, tenantPerms.AllowedActions...),
		})
	}

	return NormalizeOpenSearchRoleSpec(spec), nil
}

// NormalizeOpenSearchRoleSpec returns a deterministic representation suitable
// for role naming and static credential matching.
func NormalizeOpenSearchRoleSpec(spec OpenSearchRoleSpec) OpenSearchRoleSpec {
	normalized := OpenSearchRoleSpec{
		ClusterPermissions: uniqueSorted(spec.ClusterPermissions),
	}

	indexGroups := make(map[string]OpenSearchIndexPermissionSpec)
	for _, perm := range spec.IndexPermissions {
		actions := uniqueSorted(perm.AllowedActions)
		patterns := uniqueSorted(perm.IndexPatterns)
		if len(actions) == 0 || len(patterns) == 0 {
			continue
		}
		fls := uniqueSorted(perm.FLS)
		masked := uniqueSorted(perm.MaskedFields)
		key := strings.Join(actions, "\x00") + "\x01" + strings.TrimSpace(perm.DLS) + "\x01" + strings.Join(fls, "\x00") + "\x01" + strings.Join(masked, "\x00")
		group := indexGroups[key]
		group.AllowedActions = actions
		group.DLS = strings.TrimSpace(perm.DLS)
		group.FLS = fls
		group.MaskedFields = masked
		group.IndexPatterns = uniqueSorted(append(group.IndexPatterns, patterns...))
		indexGroups[key] = group
	}
	for _, group := range indexGroups {
		normalized.IndexPermissions = append(normalized.IndexPermissions, group)
	}
	sort.Slice(normalized.IndexPermissions, func(i, j int) bool {
		a := normalized.IndexPermissions[i]
		b := normalized.IndexPermissions[j]
		return strings.Join(a.IndexPatterns, "\x00")+strings.Join(a.AllowedActions, "\x00") <
			strings.Join(b.IndexPatterns, "\x00")+strings.Join(b.AllowedActions, "\x00")
	})

	tenantGroups := make(map[string]OpenSearchTenantPermissionSpec)
	for _, perm := range spec.TenantPermissions {
		actions := uniqueSorted(perm.AllowedActions)
		patterns := uniqueSorted(perm.TenantPatterns)
		if len(actions) == 0 || len(patterns) == 0 {
			continue
		}
		key := strings.Join(actions, "\x00")
		group := tenantGroups[key]
		group.AllowedActions = actions
		group.TenantPatterns = uniqueSorted(append(group.TenantPatterns, patterns...))
		tenantGroups[key] = group
	}
	for _, group := range tenantGroups {
		normalized.TenantPermissions = append(normalized.TenantPermissions, group)
	}
	sort.Slice(normalized.TenantPermissions, func(i, j int) bool {
		a := normalized.TenantPermissions[i]
		b := normalized.TenantPermissions[j]
		return strings.Join(a.TenantPatterns, "\x00")+strings.Join(a.AllowedActions, "\x00") <
			strings.Join(b.TenantPatterns, "\x00")+strings.Join(b.AllowedActions, "\x00")
	})

	return normalized
}

// OpenSearchRoleSignature returns a stable string for a normalized role spec.
func OpenSearchRoleSignature(spec OpenSearchRoleSpec) string {
	normalized := NormalizeOpenSearchRoleSpec(spec)
	data, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	return string(data)
}

// OpenSearchRoleName returns a deterministic OpenSearch role name for a grant
// set.
func OpenSearchRoleName(spec OpenSearchRoleSpec) string {
	sum := sha256.Sum256([]byte(OpenSearchRoleSignature(spec)))
	return "wp_os_role_" + hex.EncodeToString(sum[:8])
}

// IsEmptyOpenSearchRoleSpec reports whether the spec grants no permissions.
func IsEmptyOpenSearchRoleSpec(spec OpenSearchRoleSpec) bool {
	spec = NormalizeOpenSearchRoleSpec(spec)
	return len(spec.ClusterPermissions) == 0 && len(spec.IndexPermissions) == 0 && len(spec.TenantPermissions) == 0
}

// EnsureUser creates or updates an OpenSearch Security role and internal user
// for the given identity. Returns backend Basic auth credentials.
func (p *OpenSearchProvisioner) EnsureUser(ctx context.Context, loginName, nodeName string, spec OpenSearchRoleSpec) (string, string, error) {
	tracer := otel.Tracer("waypoint")
	ctx, span := tracer.Start(ctx, "waypoint.opensearch.provision.ensure_user",
		trace.WithAttributes(
			attribute.String("waypoint.user", loginName),
			attribute.Int("waypoint.index_permission_count", len(spec.IndexPermissions)),
		),
	)
	defer span.End()
	if p.peerService != "" {
		span.SetAttributes(attribute.String("peer.service", p.peerService))
	}

	spec = NormalizeOpenSearchRoleSpec(spec)
	if IsEmptyOpenSearchRoleSpec(spec) {
		err := fmt.Errorf("no OpenSearch permissions")
		span.RecordError(err)
		return "", "", err
	}

	osUser := p.formatUsername(loginName, nodeName)
	roleName := OpenSearchRoleName(spec)
	p.logger.DebugContext(ctx, "ensuring OpenSearch user", "login", loginName, "user", osUser, "role", roleName)

	release, err := p.acquireUserLock(ctx, osUser)
	if err != nil {
		span.RecordError(err)
		return "", "", err
	}
	if release != nil {
		defer release()
	}

	if cached, ok := p.credCache.Load(osUser); ok {
		cc := cached.(*cachedCredential)
		if time.Now().Before(cc.expires) {
			if err := p.ensureRole(ctx, roleName, spec); err != nil {
				span.RecordError(err)
				return "", "", fmt.Errorf("ensure role: %w", err)
			}
			if err := p.ensureInternalUser(ctx, osUser, cc.password, roleName); err != nil {
				span.RecordError(err)
				return "", "", fmt.Errorf("ensure internal user: %w", err)
			}
			if p.store != nil {
				p.store.TouchLastUsed(ctx, osUser)
			}
			return osUser, cc.password, nil
		}
	}

	password := generatePassword()

	if err := p.ensureRole(ctx, roleName, spec); err != nil {
		span.RecordError(err)
		return "", "", fmt.Errorf("ensure role: %w", err)
	}
	if err := p.ensureInternalUser(ctx, osUser, password, roleName); err != nil {
		span.RecordError(err)
		return "", "", fmt.Errorf("ensure internal user: %w", err)
	}

	p.credCache.Store(osUser, &cachedCredential{
		password: password,
		expires:  time.Now().Add(credentialTTL),
	})
	if p.store != nil {
		p.store.TouchLastUsed(ctx, osUser)
	}

	return osUser, password, nil
}

func (p *OpenSearchProvisioner) acquireUserLock(ctx context.Context, username string) (func(), error) {
	if p.store == nil {
		return nil, nil
	}

	const lockTTL = 30 * time.Second
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	var lockToken string
	lockName := "opensearch:user:" + username
	for i := 0; i < maxRetries; i++ {
		token, err := p.store.AcquireLock(ctx, lockName, lockTTL)
		if err != nil {
			return nil, fmt.Errorf("acquire lock: %w", err)
		}
		if token != "" {
			lockToken = token
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	if lockToken == "" {
		return nil, fmt.Errorf("could not acquire lock for user %q", username)
	}

	return func() {
		if err := p.store.ReleaseLock(context.Background(), lockName, lockToken); err != nil {
			p.logger.Error("failed to release OpenSearch user lock", "user", username, "error", err)
		}
	}, nil
}

func (p *OpenSearchProvisioner) ensureRole(ctx context.Context, roleName string, spec OpenSearchRoleSpec) error {
	ctx, span := otel.Tracer("waypoint").Start(ctx, "waypoint.opensearch.provision.ensure_role",
		trace.WithAttributes(attribute.String("waypoint.opensearch_role", roleName)),
	)
	defer span.End()

	err := p.doJSON(ctx, http.MethodPut, "/_plugins/_security/api/roles/"+url.PathEscape(roleName), spec, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "ensure role failed")
	}
	return err
}

func (p *OpenSearchProvisioner) ensureInternalUser(ctx context.Context, username, password, roleName string) error {
	ctx, span := otel.Tracer("waypoint").Start(ctx, "waypoint.opensearch.provision.ensure_internal_user",
		trace.WithAttributes(attribute.String("waypoint.opensearch_user", username)),
	)
	defer span.End()

	body := map[string]any{
		"password":                  password,
		"opendistro_security_roles": []string{roleName},
	}
	err := p.doJSON(ctx, http.MethodPut, "/_plugins/_security/api/internalusers/"+url.PathEscape(username), body, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "ensure internal user failed")
	}
	return err
}

func (p *OpenSearchProvisioner) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var payload []byte
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		payload = data
	}

	u := *p.adminURL
	u.Path = strings.TrimRight(p.adminURL.Path, "/") + path
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := p.auth.Authenticate(ctx, req, payload); err != nil {
		return fmt.Errorf("authenticate request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s failed: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// formatUsername builds: {prefix}{login_sanitized}_{node}. Truncated to 128
// chars with a hash suffix for uniqueness.
func (p *OpenSearchProvisioner) formatUsername(loginName, nodeName string) string {
	sanitized := sanitize(loginName)
	node := sanitize(nodeName)

	name := fmt.Sprintf("%s%s_%s", p.userPrefix, sanitized, node)
	if len(name) <= 128 {
		return name
	}

	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:4])
	return name[:128-9] + "_" + suffix
}

func expandOpenSearchPresetActions(presets []string) ([]string, []string, error) {
	var cluster []string
	var actions []string
	for _, preset := range presets {
		switch strings.ToLower(strings.TrimSpace(preset)) {
		case "":
			continue
		case "readonly":
			cluster = append(cluster, "cluster_composite_ops_ro")
			actions = append(actions, "read")
		case "readwrite":
			cluster = append(cluster, "cluster_composite_ops")
			actions = append(actions, "read", "write", "create_index")
		case "admin":
			cluster = append(cluster, "cluster_all")
			actions = append(actions, "indices_all")
		default:
			return nil, nil, fmt.Errorf("unknown OpenSearch preset %q; valid presets: %s",
				preset, strings.Join(OpenSearchPresetNames, ", "))
		}
	}
	return cluster, actions, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
