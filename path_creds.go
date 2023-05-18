package huaweicloud

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/hashicorp/go-uuid"
    "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
    "strings"
    "time"
    "vault-plugin-secrets-huaweicloud/clients"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathCreds() *framework.Path {
    return &framework.Path{
        Pattern: "creds/" + framework.GenericNameRegex("name"),
        Fields: map[string]*framework.FieldSchema{
            "name": {
                Type:        framework.TypeLowerCaseString,
                Description: "The name of the role.",
            },
        },
        Callbacks: map[logical.Operation]framework.OperationFunc{
            logical.ReadOperation: b.operationCredsRead,
        },
        HelpSynopsis:    pathCredsHelpSyn,
        HelpDescription: pathCredsHelpDesc,
    }
}

func (b *backend) operationCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    roleName := data.Get("name").(string)
    if roleName == "" {
        return nil, errors.New("name is required")
    }

    role, err := readRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }
    if role == nil {
        // Attempting to read a role that doesn't exist.
        return nil, nil
    }

    creds, err := readCredentials(ctx, req.Storage)
    if err != nil {
        return nil, err
    }
    if creds == nil {
        return nil, errors.New("unable to create secret because no credentials are configured")
    }

    iamClient, err := clients.NewIamClient(creds.AccessKey, creds.SecretKey)
    if err != nil {
        return nil, err
    }
    if iamClient == nil {
        return nil, errors.New("unable to get iam client")
    }
    switch role.CredentialType {
    case iam_user:
        isSucess := false
        userName := generateName(roleName, 32)
        userDescription := "create by vault"
        createUserRequest := &model.CreateUserRequest{
            Body: &model.CreateUserRequestBody{
                User: &model.CreateUserOption{
                    Name:        userName,
                    DomainId:    role.DomainId,
                    Description: &userDescription,
                },
            },
        }
        createUserResponse, err := iamClient.CreateUser(createUserRequest)
        if err != nil {
            return nil, err
        }
        if createUserResponse != nil && createUserResponse.HttpStatusCode != 201 {
            b.Logger().Error(fmt.Sprintf("unable to create user, userName: %s, httpcode:%d", createUserRequest.Body.User.Name, createUserResponse.HttpStatusCode))
        }
        defer func() {
            if isSucess {
                return
            }
            deleteUserRequest := &model.KeystoneDeleteUserRequest{
                UserId: createUserResponse.User.Id,
            }
            deleteUserResponse, err := iamClient.KeystoneDeleteUser(deleteUserRequest)
            if err != nil {
                b.Logger().Error(fmt.Sprintf("unable to delete user, userId: %s ", deleteUserRequest.UserId), err);
            }
            if deleteUserResponse != nil && deleteUserResponse.HttpStatusCode != 204 {
                b.Logger().Error(fmt.Sprintf("unable to delete user, userId: %s, httpcode:%d", deleteUserRequest.UserId, deleteUserResponse.HttpStatusCode))
            }
        }()
        groupDescription := "create by vault"
        groupName := generateName(roleName, 32)
        createGroupRequest := &model.KeystoneCreateGroupRequest{
            Body: &model.KeystoneCreateGroupRequestBody{
                Group: &model.KeystoneCreateGroupOption{
                    Name:        groupName,
                    Description: &groupDescription,
                },
            },
        }
        // create user group
        createGroupResponse, err := iamClient.KeystoneCreateGroup(createGroupRequest)
        if err != nil {
            return nil, err
        }
        if createGroupResponse != nil && createGroupResponse.HttpStatusCode != 201 {
            err := errors.New(fmt.Sprintf("unable to create user group, groupName: %s, httpcode:%d", createGroupRequest.Body.Group.Name, createGroupResponse.HttpStatusCode))
            return nil, err
        }
        defer func() {
            if isSucess {
                return
            }
            deleteGroupRequest := &model.KeystoneDeleteGroupRequest{
                GroupId: createGroupResponse.Group.Id,
            }
            deleteGroupResponse, e := iamClient.KeystoneDeleteGroup(deleteGroupRequest)
            if e != nil {
                b.Logger().Error(fmt.Sprintf("unable to delete user group, groupName: %s", createGroupRequest.Body.Group.Name), e)
            }
            if deleteGroupResponse != nil && deleteGroupResponse.HttpStatusCode != 204 {
                b.Logger().Error(fmt.Sprintf("unable to delete user group, groupName: %s, httpcode:%d", createGroupRequest.Body.Group.Name, deleteGroupResponse.HttpStatusCode))
            }
        }()
        custom_policy_id := ""
        if role.PolicyDocuments != nil && len(role.PolicyDocuments) > 0 {
            policyName := generateName(roleName, 32)
            // create policy
            statements, err := parsePolicyDocuments(role.PolicyDocuments)
            if err != nil {
                return nil, err
            }
            createPolicyRequest := &model.CreateCloudServiceCustomPolicyRequest{
                Body: &model.CreateCloudServiceCustomPolicyRequestBody{
                    Role: &model.ServicePolicyRoleOption{
                        DisplayName: policyName,
                        Type:        "XA",
                        Description: "create policy by vault",
                        Policy: &model.ServicePolicy{
                            Version:   "1.1",
                            Statement: statements,
                        },
                    },
                },
            }
            createPolicyResponse, err := iamClient.CreateCloudServiceCustomPolicy(createPolicyRequest)
            if err != nil {
                return nil, err
            }
            if createPolicyResponse != nil && createPolicyResponse.HttpStatusCode != 201 {
                err := errors.New(fmt.Sprintf("unable to create custom policy, roleName: %s, httpcode:%d", createPolicyRequest.Body.Role.DisplayName, createPolicyResponse.HttpStatusCode))
                return nil, err
            }
            custom_policy_id = createPolicyResponse.Role.Id
            defer func() {
                if isSucess {
                    return
                }
                deletePolicyRequest := &model.DeleteCustomPolicyRequest{
                    RoleId: createPolicyResponse.Role.Id,
                }
                deletePolicyResponse, e := iamClient.DeleteCustomPolicy(deletePolicyRequest)
                if e != nil {
                    b.Logger().Error(fmt.Sprintf("unable to delete custom policy, roleId: %s", deletePolicyRequest.RoleId), e)
                }
                if deletePolicyResponse != nil && deletePolicyResponse.HttpStatusCode != 200 {
                    b.Logger().Error(fmt.Sprintf("unable to delete custom policy, roleId: %s, httpcode:%d", deletePolicyRequest.RoleId, deletePolicyResponse.HttpStatusCode))
                }
            }()
            // bind custom policy(policyDocuments) to user group
            bindPolicyRequest := &model.UpdateDomainGroupInheritRoleRequest{
                DomainId: creds.DomainId,
                GroupId:  createGroupResponse.Group.Id,
                RoleId:   createPolicyResponse.Role.Id,
            }
            bindPolicyResponse, err := iamClient.UpdateDomainGroupInheritRole(bindPolicyRequest)
            if err != nil {
                return nil, err
            }
            if bindPolicyResponse != nil && bindPolicyResponse.HttpStatusCode != 204 {
                err := errors.New(fmt.Sprintf("unable to bind policy, roleName:%s, policyName:%s", roleName, createPolicyRequest.Body.Role.DisplayName))
                return nil, err
            }
            defer func() {
                if isSucess {
                    return
                }
                unBindPolicyRequest := &model.DeleteDomainGroupInheritedRoleRequest{
                    DomainId: creds.DomainId,
                    GroupId:  createGroupResponse.Group.Id,
                    RoleId:   createPolicyResponse.Role.Id,
                }
                unBindPolicyResponse, e := iamClient.DeleteDomainGroupInheritedRole(unBindPolicyRequest)
                if e != nil {
                    b.Logger().Error(fmt.Sprintf("unable to delete bind policy, roleId: %s, groupId：%s, domainId: %s", unBindPolicyRequest.RoleId, unBindPolicyRequest.GroupId, unBindPolicyRequest.DomainId), e)
                }
                if unBindPolicyResponse != nil && unBindPolicyResponse.HttpStatusCode != 204 {
                    b.Logger().Error(fmt.Sprintf("unable to delete bind policy, roleId: %s, groupId：%s, domainId: %s, httpcode: %d", unBindPolicyRequest.RoleId, unBindPolicyRequest.GroupId, unBindPolicyRequest.DomainId, unBindPolicyResponse.HttpStatusCode))
                }
            }()
        }
        // bind policies existing on the cloud console to user groups
        if role.Policies != nil && len(role.Policies) > 0 {
            for _, policy := range role.Policies {
                permissionsResponse, err := iamClient.KeystoneListPermissions(&model.KeystoneListPermissionsRequest{
                    DisplayName: &policy,
                })
                if err != nil {
                    return nil, err
                }
                if permissionsResponse != nil && permissionsResponse.HttpStatusCode != 200 {
                    return nil, fmt.Errorf("unable to find policy: %s,httpcode: %d", policy, permissionsResponse.HttpStatusCode)
                }

                if len(*permissionsResponse.Roles) > 0 {
                    roleId := (*permissionsResponse.Roles)[0].Id
                    bindPolicyRequest := &model.UpdateDomainGroupInheritRoleRequest{
                        DomainId: creds.DomainId,
                        GroupId:  createGroupResponse.Group.Id,
                        RoleId:   roleId,
                    }
                    bindPolicyResponse, err := iamClient.UpdateDomainGroupInheritRole(bindPolicyRequest)
                    if err != nil {
                        return nil, err
                    }
                    if bindPolicyResponse != nil && bindPolicyResponse.HttpStatusCode != 204 {
                        err := errors.New(fmt.Sprintf("unable to bind policy, roleName:%s, policyName:%s", roleName, policy))
                        return nil, err
                    }
                    defer func() {
                        if isSucess {
                            return
                        }
                        unBindPolicyRequest := &model.DeleteDomainGroupInheritedRoleRequest{
                            DomainId: creds.DomainId,
                            GroupId:  createGroupResponse.Group.Id,
                            RoleId:   roleId,
                        }
                        unBindPolicyResponse, e := iamClient.DeleteDomainGroupInheritedRole(unBindPolicyRequest)
                        if e != nil {
                            b.Logger().Error(fmt.Sprintf("unable to delete bind policy, roleId: %s, groupId：%s, domainId: %s", unBindPolicyRequest.RoleId, unBindPolicyRequest.GroupId, unBindPolicyRequest.DomainId), e)
                        }
                        if unBindPolicyResponse != nil && unBindPolicyResponse.HttpStatusCode != 204 {
                            b.Logger().Error(fmt.Sprintf("unable to delete bind policy, roleId: %s, groupId：%s, domainId: %s, httpcode: %d", unBindPolicyRequest.RoleId, unBindPolicyRequest.GroupId, unBindPolicyRequest.DomainId, unBindPolicyResponse.HttpStatusCode))
                        }
                    }()
                }
            }
        }
        // add user to user group
        addUserToGroupRequest := &model.KeystoneAddUserToGroupRequest{
            GroupId: createGroupResponse.Group.Id,
            UserId:  createUserResponse.User.Id,
        }
        addUserToGroupResponse, err := iamClient.KeystoneAddUserToGroup(addUserToGroupRequest)
        if err != nil {
            return nil, err
        }
        if addUserToGroupResponse == nil || addUserToGroupResponse.HttpStatusCode != 204 {
            err := errors.New(fmt.Sprintf("unable to add user to group, userName:%s, groupName:%s", createUserRequest.Body.User.Name, createGroupRequest.Body.Group.Name))
            return nil, err
        }
        isSucess = true
        permanentDescription := "create by vault"
        permanentRequest := &model.CreatePermanentAccessKeyRequest{
            Body: &model.CreatePermanentAccessKeyRequestBody{
                Credential: &model.CreateCredentialOption{
                    UserId:      createUserResponse.User.Id,
                    Description: &permanentDescription,
                },
            },
        }
        permanentResponse, err := iamClient.CreatePermanentAccessKey(permanentRequest)
        if err != nil {
            return nil, err
        }
        if permanentResponse == nil || permanentResponse.Credential == nil {
            return nil, errors.New("create credential failed ")
        }
        resp := b.Secret(secretType).Response(map[string]interface{}{
            "access_key": permanentResponse.Credential.Access,
            "secret_key": permanentResponse.Credential.Secret,
        }, map[string]interface{}{
            "role_name":  roleName,
            "role_type":  role.CredentialType,
            "user_id":    createUserResponse.User.Id,
            "domain_id":  creds.DomainId,
            "policy_id":  custom_policy_id,
            "access_key": permanentResponse.Credential.Access,
            "group_id":   createGroupResponse.Group.Id,
        })
        return resp, nil
    case assume_role:
        tokenDurationSeconds := int32(role.DurationSeconds.Seconds())
        statements, err := parsePolicyDocuments(role.PolicyDocuments)
        if err != nil {
            return nil, err
        }
        request := &model.CreateTemporaryAccessKeyByAgencyRequest{
            Body: &model.CreateTemporaryAccessKeyByAgencyRequestBody{
                Auth: &model.AgencyAuth{
                    Identity: &model.AgencyAuthIdentity{
                        Methods: []model.AgencyAuthIdentityMethods{
                            model.GetAgencyAuthIdentityMethodsEnum().ASSUME_ROLE,
                        },
                        AssumeRole: &model.IdentityAssumerole{
                            AgencyName:      role.AgencyName,
                            DomainId:        &role.DomainId,
                            DurationSeconds: &tokenDurationSeconds,
                        },
                        Policy: &model.ServicePolicy{
                            Version:   "1.1",
                            Statement: statements,
                        },
                    },
                },
            },
        }
        temporaryResponse, err := iamClient.CreateTemporaryAccessKeyByAgency(request)
        if err != nil {
            return nil, err
        }
        if temporaryResponse == nil || temporaryResponse.Credential == nil {
            return nil, errors.New("create credential failed ")
        }
        resp := b.Secret(secretType).Response(map[string]interface{}{
            "access_key":    temporaryResponse.Credential.Access,
            "secret_key":    temporaryResponse.Credential.Secret,
            "security_token": temporaryResponse.Credential.Securitytoken,
            "expiration":    temporaryResponse.Credential.ExpiresAt,
        }, map[string]interface{}{
            "role_type": role.CredentialType,
        })
        return resp, nil
    case token:
        tokenDurationSeconds := int32(role.DurationSeconds.Seconds())
        statements, err := parsePolicyDocuments(role.PolicyDocuments)
        if err != nil {
            return nil, err
        }
        request := &model.CreateTemporaryAccessKeyByTokenRequest{
            Body: &model.CreateTemporaryAccessKeyByTokenRequestBody{
                Auth: &model.TokenAuth{
                    Identity: &model.TokenAuthIdentity{
                        Methods: []model.TokenAuthIdentityMethods{
                            model.GetTokenAuthIdentityMethodsEnum().TOKEN,
                        },
                        Token: &model.IdentityToken{
                            DurationSeconds: &tokenDurationSeconds,
                        },
                        Policy: &model.ServicePolicy{
                            Version:   "1.1",
                            Statement: statements,
                        },
                    },
                },
            },
        }
        temporaryResponse, err := iamClient.CreateTemporaryAccessKeyByToken(request)
        if err != nil {
            return nil, err
        }
        if temporaryResponse == nil || temporaryResponse.Credential == nil {
            return nil, errors.New("create credential failed ")
        }
        resp := b.Secret(secretType).Response(map[string]interface{}{
            "access_key":    temporaryResponse.Credential.Access,
            "secret_key":    temporaryResponse.Credential.Secret,
            "security_token": temporaryResponse.Credential.Securitytoken,
            "expiration":    temporaryResponse.Credential.ExpiresAt,
        }, map[string]interface{}{
            "role_type": role.CredentialType,
        })
        return resp, nil
    }
    return nil, nil
}

func parsePolicyDocuments(policyDocuments []*policyDocument) ([]model.ServiceStatement, error) {
    serviceStatements := make([]model.ServiceStatement, len(policyDocuments))
    for index, policyDocument := range policyDocuments {
        if statements := policyDocument.PolicyDocument["Statement"]; statements != nil {
            var statements_inputs []model.ServiceStatement
            statements_bytes, err := json.Marshal(statements)
            if err != nil {
                return nil, err
            }
            err = json.Unmarshal(statements_bytes, &statements_inputs)
            if err != nil {
                return nil, err
            }
            serviceStatements[index] = statements_inputs[0]
        }
    }
    return serviceStatements, nil
}

func generateName(roleName string, maxLength int) string {
    // The time and random number take up to 15 more in length, so if the name
    // is too long we need to trim it.
    if len(roleName) > 24 {
        roleName = roleName[:24]
    }
    uid, err := uuid.GenerateUUID()
    if err != nil {
        uid = fmt.Sprint(time.Now().Unix())
    }
    uid = strings.Replace(uid, "-", "", -1)
    if len(uid) > maxLength-len(roleName) {
        uid = uid[:maxLength-len(roleName)-1]
    }
    return fmt.Sprintf("%s-%s", roleName, uid)
}

const pathCredsHelpSyn = `
Generate a permanent or temporary credential using the given role's configuration.'
`
const pathCredsHelpDesc = `
This path will generate a permanent or temporary(create by assume role and token) credential for
accessing Huaweicloud. The policies used to back this key pair will be
configured on the role. For example, if this backend is mounted at "huaweicloud",
then "huaweicloud/creds/deploy" would generate access keys for the "deploy" role.

The permanent or temporary credential will have a ttl associated with it. the permanent credential can
be renewed or revoked as described here: 
https://www.vaultproject.io/docs/concepts/lease.html,
but temporary credentials do not support renewal or revocation.
`
