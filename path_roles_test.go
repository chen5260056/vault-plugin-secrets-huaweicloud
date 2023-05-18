package huaweicloud

import (
    "context"
    "fmt"
    "github.com/hashicorp/vault/sdk/logical"
    "testing"
)

var (
    roleName        = "huaweicloud"
    policies        = [2]string{"ELB FullAccess", "AutoScaling FullAccess"}
    policyDocuments = `[
	{
		"Version": "1.1",
		"Statement": [
			{
				"Action": [
					"ecs:*:*"
				],
				"Effect": "Allow"
			}
		]
	},
	{
		"Version": "1.1",
		"Statement": [
			{
				"Action": [
					"obs:*:*"
				],
				"Effect": "Allow"
			}
		]
	}
]`
)

func TestRoles(t *testing.T) {
    env := initEnv()
    t.Run("createIamUser", env.createIamUser)
    t.Run("createTokenRoles", env.createTokenRoles)
    t.Run("createTokenRoles", env.createTokenRoles)
}

func (env *envInfo) createIamUser(t *testing.T) {
    b := env.Backend
    request := &logical.Request{
        Path:      fmt.Sprintf("role/%s", roleName),
        Operation: logical.CreateOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "credential_type":  "iam_user",
            "domain_id":        env.DomainId,
            "access_key":       env.AccessKey,
            "secret_key":       env.SecretKey,
            "policy_documents": policyDocuments,
            "policies":         policies,
            "ttl":              30,
            "max_ttl":          150,
        },
    }
    _, e := b.HandleRequest(context.Background(), request)
    assertErrorNotNil(t, e)
}

func (env *envInfo) createTokenRoles(t *testing.T) {
    b := env.Backend
    request := &logical.Request{
        Path:      fmt.Sprintf("role/%s", roleName),
        Operation: logical.CreateOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "credential_type":  "token",
            "domain_id":        env.DomainId,
            "access_key":       env.AccessKey,
            "secret_key":       env.SecretKey,
            "duration_seconds": 1200,
            "policy_documents": policyDocuments,
        },
    }
    _, e := b.HandleRequest(context.Background(), request)
    assertErrorNotNil(t, e)
}

func (env *envInfo) createAssumeRoles(t *testing.T) {
    b := env.Backend
    request := &logical.Request{
        Path:      fmt.Sprintf("role/%s", roleName),
        Operation: logical.CreateOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "credential_type":  "assume_role",
            "domain_id":        env.DomainId,
            "access_key":       env.AccessKey,
            "secret_key":       env.SecretKey,
            "agency_name":     "muyi-account",
            "duration_seconds": 1200,
            "policy_documents": policyDocuments,
        },
    }
    _, e := b.HandleRequest(context.Background(), request)
    assertErrorNotNil(t, e)
}
