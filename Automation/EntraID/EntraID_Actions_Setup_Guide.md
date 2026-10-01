# EntraID Actions Setup Guide

This small guide explains how to prepare Microsoft Entra ID and Microsoft Graph for this AAM actions.

## Actions Included

| Action file                      | Purpose                                                                 | Microsoft Graph operation                                        |
|----------------------------------|-------------------------------------------------------------------------|------------------------------------------------------------------|
| EntraID_Action_RevokeSession.py  | Revoke a user's active sign-in sessions                                 | POST /users/{id or userPrincipalName}/revokeSignInSessions       |
| EntraID_Action_ChangePassword.py | Generate a temporary password and force password change at next sign-in | PATCH /users/{id or userPrincipalName} with passwordProfile      |
| EntraID_Action_DisableUser.py    | Disable the user account                                                | PATCH /users/{id or userPrincipalName} with accountEnabled=false |
| EntraID_Action_EnableUser.py     | Enable the user account                                                 | PATCH /users/{id or userPrincipalName} with accountEnabled=true  |
| EntraID_Action_LockUser.py       | Disable the account and revoke sessions                                 | PATCH accountEnabled=false, then POST revokeSignInSessions       |

Note: Microsoft Graph does not provide a separate generic lock user or unlock user endpoint for these action patterns. In this implementation, Lock User means block sign-in by setting accountEnabled to false and revoke sessions. 
The user target is passed as an action input named user_id. The value can be the user's Microsoft Graph object ID or userPrincipalName.

## Step 1: Create Or Select An App Registration

1. Open the Microsoft Entra admin center.
2. Go to Identity > Applications > App registrations.
3. Create a new registration or select an existing integration app.
4. Save these values:
   - Directory tenant ID
   - Application client ID
5. Create a client secret under Certificates & secrets.
6. Save the secret value immediately. It is only shown once.

The actions use the OAuth 2.0 client credentials flow and request tokens from:

```text
https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
```

The token scope used by the actions is:

```text
https://graph.microsoft.com/.default
```

## Step 2: Add Microsoft Graph Application Permissions

In the app registration:

1. Go to API permissions.
2. Choose Add a permission.
3. Select Microsoft Graph.
4. Select Application permissions.
5. Add the permissions required for the actions you plan to enable.
6. Select Grant admin consent.

### Minimum Permission Matrix

| Action          | Required Microsoft Graph application permissions                          |
|-----------------|---------------------------------------------------------------------------|
| Revoke Session  | User.RevokeSessions.All                                                   |
| Change Password | User-PasswordProfile.ReadWrite.All                                        |
| Disable User    | User.EnableDisableAccount.All and User.Read.All                           |
| Enable User     | User.EnableDisableAccount.All and User.Read.All                           |
| Lock User       | User.EnableDisableAccount.All, User.Read.All, and User.RevokeSessions.All |

Admin consent is required for Microsoft Graph application permissions.

## Step 3: Assign Required Entra Directory Role To The App

Some user update operations require more than Graph API permissions.

1. Open Microsoft Entra admin center.
2. Go to Identity > Roles & admins.
3. Assign the app service principal an appropriate role for the operations you need.
4. For password changes, use at least User Administrator for non-admin users.
5. For administrator accounts or sensitive targets, use a role that is allowed to manage that target class, such as Privileged Authentication Administrator where required by your tenant policy.

## Common Errors

| Error                                             | Likely cause                                                                                            |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| invalid_client                                    | Wrong client_id or client_secret, expired secret, or wrong tenant_id                                    |
| Authorization_RequestDenied                       | Missing Graph permission, missing admin consent, or missing directory role assignment                   |
| Insufficient privileges to complete the operation | The app has Graph permission but lacks a required Entra directory role or cannot manage the target user |
| Request_BadRequest during password update         | Password violates tenant policy, user is federated, or passwordProfile cannot be updated for that user  |
| 404 user not found                                | user_id value is wrong, from another tenant, or not URL-resolvable as object ID/userPrincipalName       |

## Microsoft References

- Microsoft Graph overview: https://learn.microsoft.com/en-us/graph/overview
- Client credentials flow for Microsoft Graph: https://learn.microsoft.com/en-us/graph/auth-v2-service
- Revoke sign-in sessions: https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
- Update user: https://learn.microsoft.com/en-us/graph/api/user-update

## Appendix: Action Inputs

### Revoke Session

File: EntraID_Action_RevokeSession.py

| Input   | Description                         |
|---------|-------------------------------------|
| user_id | User object ID or userPrincipalName |

Revoke sessions can take a few minutes to fully invalidate refresh tokens.

### Change Password

File: EntraID_Action_ChangePassword.py

| Input   | Description                         |
|---------|-------------------------------------|
| user_id | User object ID or userPrincipalName |

No additional action inputs are required. The action generates a strong temporary password, sets forceChangePasswordNextSignIn to true, and returns the generated password once in the action response.

The generated password must still satisfy the tenant password policy. Treat the returned password as a secret and share it only through an approved secure channel.

### Disable User

File: EntraID_Action_DisableUser.py

| Input   | Description                         |
|---------|-------------------------------------|
| user_id | User object ID or userPrincipalName |

This sets accountEnabled to false.

### Enable User

File: EntraID_Action_EnableUser.py

| Input   | Description                         |
|---------|-------------------------------------|
| user_id | User object ID or userPrincipalName |

This sets accountEnabled to true.

### Lock User

File: EntraID_Action_LockUser.py

| Input   | Description                         |
|---------|-------------------------------------|
| user_id | User object ID or userPrincipalName |

This sets accountEnabled to false and then revokes sign-in sessions.