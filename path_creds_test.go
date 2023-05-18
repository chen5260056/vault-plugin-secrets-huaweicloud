package huaweicloud

import (
    "context"
    "fmt"
    "github.com/hashicorp/vault/sdk/logical"
    "testing"
)

func TestGenerateAccess(t *testing.T) {
    env := initEnv()
    t.Run("testGenerateIamUserAccesskey", env.testGenerateIamUserAccesskey)
    t.Run("testGenerateAssumeRoleAccesskey", env.testGenerateAssumeRoleAccesskey)
    t.Run("testGenerateTokenAccesskey", env.testGenerateTokenAccesskey)
}

func (env *envInfo) testGenerateIamUserAccesskey(t *testing.T) {
    env.createConfig(t)
    env.createIamUser(t)
    response, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Path:      fmt.Sprintf("creds/%s", roleName),
        Operation: logical.ReadOperation,
        Storage:   env.Storage,
    })
    fmt.Println(response)
    assertErrorNotNil(t, e)
    env.Secret = response.Secret
}

func (env *envInfo) testGenerateAssumeRoleAccesskey(t *testing.T) {
    env.createConfig(t)
    env.createAssumeRoles(t)
    response, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Path:      fmt.Sprintf("creds/%s", roleName),
        Operation: logical.ReadOperation,
        Storage:   env.Storage,
    })
    assertErrorNotNil(t, e)
    env.Secret = response.Secret
    fmt.Println(response)
}

func (env *envInfo) testGenerateTokenAccesskey(t *testing.T) {
    env.createConfig(t)
    env.createTokenRoles(t)
    response, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Path:      fmt.Sprintf("creds/%s", roleName),
        Operation: logical.ReadOperation,
        Storage:   env.Storage,
    })
    assertErrorNotNil(t, e)
    env.Secret = response.Secret
    fmt.Println(response)
}