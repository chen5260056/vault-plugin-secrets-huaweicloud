package huaweicloud

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func  Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() logical.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRole(),
			b.pathListRoles(),
			b.pathCreds(),
		},
		Secrets: []*framework.Secret{
			b.pathSecrets(),
		},
		BackendType: logical.TypeLogical,
	}
	return b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The Huaweicloud backend dynamically generates Huaweicloud access keys for a set of
IAM policies. The Huaweicloud access keys have a configurable ttl set and
are automatically revoked at the end of the ttl.

After mounting this backend, credentials to generate IAM keys must
be configured and roles must be written using
the "role/" endpoints before any access keys can be generated.
`
