package huaweicloud

import (
    "context"
    "errors"
    "fmt"
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
    "vault-plugin-secrets-huaweicloud/clients"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

const secretType = "huaweicloud"

func (b *backend) pathSecrets() *framework.Secret {
    return &framework.Secret{
        Type: secretType,
        Fields: map[string]*framework.FieldSchema{
            "access_key": {
                Type:        framework.TypeString,
                Description: "Access Key",
            },
            "secret_key": {
                Type:        framework.TypeString,
                Description: "Secret Key",
            },
            "domain_id": {
                Type:        framework.TypeString,
                Description: "Domain Id",
            },
        },
        Renew:  b.operationRenew,
        Revoke: b.operationRevoke,
    }
}

func (b *backend) operationRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleTypeRaw, ok := req.Secret.InternalData["role_type"]
    if !ok {
        return nil, errors.New("role_type missing from secret")
    }

    switch roleTypeRaw {

    case iam_user:
        roleName, err := getStringValue(req.Secret.InternalData, "role_name")
        if err != nil {
            return nil, err
        }

        role, err := readRole(ctx, req.Storage, roleName)
        if err != nil {
            return nil, err
        }
        if role == nil {
            // The role has been deleted since the secret was issued or last renewed.
            // The user's expectation is probably that the caller won'nameOfRoleType continue being
            // able to perform renewals.
            return nil, fmt.Errorf("role %s has been deleted so no further renewals are allowed", roleName)
        }

        resp := &logical.Response{Secret: req.Secret}
        if role.TTL != 0 {
            resp.Secret.TTL = role.TTL
        }
        if role.MaxTTL != 0 {
            resp.Secret.MaxTTL = role.MaxTTL
        }
        return resp, nil
    case assume_role:
        return nil, nil
    case token:
        return nil, nil
    default:
        return nil, fmt.Errorf("unrecognized role_type: %s", roleTypeRaw)
    }
}

func (b *backend) operationRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
    roleTypeRaw, ok := req.Secret.InternalData["role_type"]
    if !ok {
        return nil, errors.New("role_type missing from secret")
    }

    switch roleTypeRaw {
    case iam_user:
        creds, err := readCredentials(ctx, req.Storage)
        if err != nil {
            return nil, err
        }
        if creds == nil {
            return nil, errors.New("unable to delete access key because no credentials are configured")
        }
        groupId, err := getStringValue(req.Secret.InternalData, "group_id")
        if err != nil {
            return nil, err
        }
        userId, err := getStringValue(req.Secret.InternalData, "user_id")
        if err != nil {
            return nil, err
        }
        policyId, err := getStringValue(req.Secret.InternalData, "policy_id")
        if err != nil {
            return nil, err
        }
        domainId, err := getStringValue(req.Secret.InternalData, "domain_id")
        if err != nil {
            return nil, err
        }
        iamClient, err := clients.NewIamClient(creds.AccessKey, creds.SecretKey)
        if err != nil {
            return nil, err
        }
        // remove policy from user group
        deleteDomainGroupInheritedRoleResponse, err := iamClient.DeleteDomainGroupInheritedRole(&model.DeleteDomainGroupInheritedRoleRequest{
            DomainId: domainId,
            GroupId:  groupId,
            RoleId:   policyId,
        })
        if err != nil {
            return nil, err
        }
        if deleteDomainGroupInheritedRoleResponse != nil && deleteDomainGroupInheritedRoleResponse.HttpStatusCode != 204 {
            return nil, errors.New(fmt.Sprintf("unable to delete policy, domainId: %s, groupId: %s,roleId: %s httpcode:%d", domainId, groupId, policyId, deleteDomainGroupInheritedRoleResponse.HttpStatusCode))
        }
        // delete user group
        deleteGroupResponse, err := iamClient.KeystoneDeleteGroup(&model.KeystoneDeleteGroupRequest{
            GroupId: groupId,
        })
        if err != nil {
            return nil, err
        }
        if deleteGroupResponse != nil && deleteGroupResponse.HttpStatusCode != 204 {
            return nil, errors.New(fmt.Sprintf("unable to delete user group, groupId: %s, httpcode:%d", groupId, deleteGroupResponse.HttpStatusCode))
        }
        // delete user
        deleteUserResponse, err := iamClient.KeystoneDeleteUser(&model.KeystoneDeleteUserRequest{
            UserId: userId,
        })
        if err != nil {
            return nil, err
        }
        if deleteUserResponse != nil && deleteUserResponse.HttpStatusCode != 204 {
            return nil, errors.New(fmt.Sprintf("unable to delete user, userId: %s, httpcode:%d", groupId, deleteUserResponse.HttpStatusCode))
        }
        // delete policy
        deletePolicyRequest := &model.DeleteCustomPolicyRequest{
            RoleId: policyId,
        }
        deletePolicyResponse, e := iamClient.DeleteCustomPolicy(deletePolicyRequest)
        if e != nil {
            b.Logger().Error(fmt.Sprintf("unable to delete custom policy, roleId: %s", deletePolicyRequest.RoleId), e)
        }
        if deletePolicyResponse != nil && deletePolicyResponse.HttpStatusCode != 200 {
            b.Logger().Error(fmt.Sprintf("unable to delete custom policy, roleId: %s, httpcode:%d", deletePolicyRequest.RoleId, deletePolicyResponse.HttpStatusCode))
        }
        return nil, nil
    case assume_role:
        return nil, nil
    case token:
        return nil, nil
    default:
        return nil, fmt.Errorf("unrecognized role_type: %s", roleTypeRaw)
    }
}

func getStringValue(internalData map[string]interface{}, key string) (string, error) {
    valueRaw, ok := internalData[key]
    if !ok {
        return "", fmt.Errorf("secret is missing %s internal data", key)
    }
    value, ok := valueRaw.(string)
    if !ok {
        return "", fmt.Errorf("secret is missing %s internal data", key)
    }
    return value, nil
}
