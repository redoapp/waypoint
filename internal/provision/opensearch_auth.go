package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// OpenSearchAuthenticator applies backend authentication to an outbound request
// to the OpenSearch Security REST API. payload is the exact request body that
// will be sent (nil for bodyless requests); implementations that sign the body
// (SigV4) hash it.
type OpenSearchAuthenticator interface {
	Authenticate(ctx context.Context, req *http.Request, payload []byte) error
}

// basicAuthenticator authenticates with HTTP Basic auth (an OpenSearch Security
// internal user, typically the admin/master user).
type basicAuthenticator struct {
	user string
	pass string
}

func (b basicAuthenticator) Authenticate(_ context.Context, req *http.Request, _ []byte) error {
	req.SetBasicAuth(b.user, b.pass)
	return nil
}

// sigv4Authenticator signs requests with AWS Signature Version 4, for Amazon
// OpenSearch Service domains that use IAM / fine-grained access control. The
// signing IAM identity must be mapped (in the domain's security config) to a
// backend role with permission to manage internal users and roles.
type sigv4Authenticator struct {
	creds   aws.CredentialsProvider
	signer  *v4.Signer
	region  string
	service string
}

func (s *sigv4Authenticator) Authenticate(ctx context.Context, req *http.Request, payload []byte) error {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	sum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(sum[:])
	// aoss requires the content hash header be present and signed; setting it
	// explicitly is also valid for es (managed) domains.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	return s.signer.SignHTTP(ctx, creds, req, payloadHash, s.service, s.region, time.Now())
}

// NewOpenSearchSigV4Authenticator builds an AWS SigV4 authenticator. Credentials
// are resolved from the default AWS chain (environment, shared config/profile,
// IRSA web identity, or EC2/ECS instance role); when roleARN is set it is
// assumed via STS on top of that base identity. Credentials are cached and
// refreshed automatically.
func NewOpenSearchSigV4Authenticator(ctx context.Context, region, service, roleARN, profile string) (OpenSearchAuthenticator, error) {
	if region == "" {
		return nil, fmt.Errorf("aws region is required for SigV4 authentication")
	}
	if service == "" {
		service = "es"
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	creds := awsCfg.Credentials
	if roleARN != "" {
		creds = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), roleARN)
	}

	return &sigv4Authenticator{
		creds:   aws.NewCredentialsCache(creds),
		signer:  v4.NewSigner(),
		region:  region,
		service: service,
	}, nil
}
