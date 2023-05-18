package clients

import (
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
    iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/region"
)

func NewIamClient(access_key, secret_key string) (*iam.IamClient, error) {
    auth := global.NewCredentialsBuilder().
        WithAk(access_key).
        WithSk(secret_key).
        Build()
    iamclient := iam.NewIamClient(
        iam.IamClientBuilder().
            WithRegion(region.ValueOf("cn-north-4")).
            WithCredential(auth).
            Build())
    return iamclient, nil
}
