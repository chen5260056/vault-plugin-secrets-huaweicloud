package huaweicloud

import (
    "context"
    "github.com/hashicorp/vault/sdk/logical"
    "os"
    "time"
)

type envInfo struct {
    AccessKey       string
    SecretKey       string
    UserId          string
    DomainId        string
    PolicyDocuments string
    Policies        []*string
    Backend         logical.Backend
    Storage         logical.Storage
    Secret          *logical.Secret
}

func initEnv() (*envInfo) {
    conf := &logical.BackendConfig{
        System: &logical.StaticSystemView{
            DefaultLeaseTTLVal: time.Hour,
            MaxLeaseTTLVal:     time.Hour,
        },
    }
    b, _ := Factory(context.Background(), conf)
    return &envInfo{
        DomainId:  os.Getenv("DOMAIN_ID"),
        AccessKey: os.Getenv("ACCESS_KEY"),
        SecretKey: os.Getenv("SECRET_KEY"),
        Backend:   b,
        Storage:   &logical.InmemStorage{},
    }
}
