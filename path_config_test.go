package huaweicloud

import (
    "context"
    "fmt"
    "github.com/hashicorp/vault/sdk/logical"
    "testing"
)

func TestConfig(t *testing.T) {
    env := initEnv()
    t.Run("createConfig", env.createConfig)
    t.Run("readConfig", env.readConfig)

}

func (env *envInfo) createConfig(t *testing.T) {
    _, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Path:      "config",
        Operation: logical.UpdateOperation,
        Storage:   env.Storage,
        Data: map[string]interface{}{
            "access_key": env.AccessKey,
            "secret_key": env.SecretKey,
            "domain_id": env.DomainId,
        },
    })
    assertErrorNotNil(t, e)
}

func (env *envInfo) readConfig(t *testing.T) {
    env.createConfig(t)
    response, e := env.Backend.HandleRequest(context.Background(), &logical.Request{
        Path:      "config",
        Operation: logical.ReadOperation,
        Storage:   env.Storage,
    })
    fmt.Print(response)
    assertErrorNotNil(t, e)
}
