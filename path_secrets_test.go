package huaweicloud

import (
    "context"
    "github.com/hashicorp/vault/sdk/logical"
    "testing"
)

func TestRenew(t *testing.T) {
    env := initEnv()
    env.createConfig(t)
    env.createIamUser(t)
    env.testGenerateIamUserAccesskey(t)
    _, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Secret:    env.Secret,
        Operation: logical.RenewOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "domain_id":  env.DomainId,
            "access_key": env.AccessKey,
            "secret_key": env.SecretKey,
        },
    })
    assertErrorNotNil(t, e)
}
func TestRevoke(t *testing.T) {
    env := initEnv()
    env.createConfig(t)
    env.createIamUser(t)
    env.testGenerateIamUserAccesskey(t)
    _, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Secret:    env.Secret,
        Operation: logical.RevokeOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "domain_id":  env.DomainId,
            "access_key": env.AccessKey,
            "secret_key": env.SecretKey,
        },
    })
    assertErrorNotNil(t, e)
}