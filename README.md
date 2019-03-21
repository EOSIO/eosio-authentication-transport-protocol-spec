# EOSIO Authentication Transport Protocol Specification

 **Specification Version**: 0.0.1

## **Transports**
### Request Transports
#### URL Query String Payload
An integrating application uses either an Apple Universal Link or a Deep Link to invoke an authenticator application, including the transaction payload in the query string as a hex-encoded value, and the recipient public key if the payload is encrypted.

* Deep Link: `{customProtocol}://request?payload={hexPayload}&key={publicKey}`
* Universal Link: `https://{siteUrl}/auth?payload={hexPayload}&key={publicKey}`

Universal Links are encouraged, as they are unique to authenticator applications and cannot be assumed by other apps installed on a user’s device.

#### Server Fetch via Another Transport (QR, etc.)
The requesting application provides a `requestUrl` in the payload. Authenticator applications will then fetch the request from the `requestUrl`. The `requestUrl` must be at the same domain or subdomain as the `referrerUrl`, if present.

This is particularly useful for outgoing transports like QR in which an entire transaction cannot be included in the initial request.

#### Server Request via Push Notification
The integrating application submits the transaction request to a push notification server and the transaction request is delivered to the user via push notification. Details of this request transport are forthcoming.

### Response Transports
#### URL Hash Fragment Identifier
Authenticator applications will return a response to the request’s `returnUrl` with the payload appended as a hex-encoded URL hash fragment identifier. If the payload is encrypted the public key is provided at the end preceded by `-`.

* URL or Universal Link: `https://{siteUrl}/some-resource/resource-id#{hexPayload}-{publicKey}`
* Deep Link:  `{customProtocol}://transaction-response#{hexPayload}-{publicKey}`

#### Webhook Callback URL
Authenticator applications will POST the transaction response to the request’s `callbackUrl` appending `/transaction/{requestId}`. E.g., `https://{siteUrl}/transaction/{requestId}`.

### Transport Encryption

Payloads should be encrypted/decrypted with the algorithm `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`.

## Request Envelope
The top level properties of each request payload make up the "request envelope". Envelopes may contain several keys:

### `version` (**required**)
The protocol version in semantic versioning format. This will help facilitate backwards-compatible protocol updates in the future.

### `id` (**required**)
The unique ID of the request as a UUIDv4. Most transports are not idempotent. This key ensures that the requesting application is able to connect a response to an initial request.

### `declaredDomain` (**required**)
Integrating applications (both web and native) must self-report a `declaredDomain`. Authenticator applications should not blindly trust this URL.

### `returnUrl` (**required**)
The URL to which an authenticator application will return the user after the request has been processed and the user has taken any necessary action. For certain response transports (e.g., `urlHashFragmentIdentifier`), the response payload will be appended to this `returnUrl`.

### `callbackUrl`
The URL an authenticator application will post the response to. Only required for some transports (e.g., `webhook`).

### `responseKey` (optional for now)
An elliptic curve 65 byte public key. If provided, the response will be encrypted with this key using the alogithm `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`

### `securityExclusions` (optional)
Integrating application developers working on integrating with a conforming authenticator application may request relaxed security settings for the sake of troubleshooting integration with an authenticator. Best practice dictates that authenticator applicationss should only respect these requests if 1) the user has explicitly enabled an authenticator's insecure mode and 2) the user has added the requesting domain to its `securityExclusion` whitelist. If both prerequisites are in place, an authenticator application may relax or ignore certain validation checks for the stated overrides.

* `addAssertToTransactions`: If `true`, an authenticator may skip adding assert actions to the transaction
* `appMetadataIntegrity`: If `true`, an authenticator may skip chain manifest and app metadata integrity checks
* `domainMatch`: If `true`, an authenticator may not enforce the same-origin policy
* `whitelistedActions`: If `true`, an authenticator may allow signing of non-manifest-whitelisted actions
* `iconIntegrity`: If `true`, an authenticator may skip app-, action-, and/or chain-icon integrity checks
* `relaxedContractParsing`: If `true`, an authenticator may allow for parsing of non-compliant Ricardian contracts

The `securityExclusion` key is only required if exclusions are being requested, and all keys will default to `false` if not explicitly listed.

### `request` (**required**)
The request payload consisting of one or more request types.

## Security and the Same-Origin Policy
At request time, authenticator applications will perform several checks:

1. assert that `referrerUrl` (if present in OS-supplied headers), `returnUrl` and `callbackUrl` are all paths of the `declaredDomain`
1. fetch `chain-manifests.json` from the root of the `declaredDomain`
1. assert that the values for `domain` declared therein all match one another and the `declaredDomain`
1. assert that the `appmeta` hashes from all chain manifests match one another
1. fetch `app-metadata.json` from the `appmeta` url in the manifest and assert that the file's hash matches the hash declared in the manifests
1. assert that any OS-supplied app identifier (e.g., bundle ID or package name) is whitelisted in the `appIdentifiers` field in `app-metadata.json` (for native applications only)

If all those checks pass, the request will be processed and the integrating application's information will be presented to the user. If any of those checks fails, an authenticator application will consider any `returnUrl` as invalid. No response will be sent to the integrating application and the authenticator application will display an error to the user.

Responses will never be sent back to domains other than the requesting domain, unless the response transport is domainless (e.g., deep link).

**TODO:** Explain what attack(s) these checks aim to prevent.

## **Request Types**
### Transport Authorization Request

**NOTE:** Transport Authorization Request is still being defined. It should stay simple at first. Something like:
* The request will include a preferred response transport.
* Action permissions will be tied only to the integrating app, not tranports.
* If the integrating app / action combination has been previously approved by the user, an authenticator application signs and send the response.

**END NOTE**

This request type carries out two functions:
1. It negotiates and establishes communication with an authenticator application over one or more transports.
1. It requests user authorization for the transaction actions that may be requested through each transport. The idea here is that integrating applications or users may restrict which actions are authorized over less secure transports.

#### Request:
* **MUST**: include a prioritized list of app-supported response transports
* **MUST**: include a list of requested action permissions for each response transport, which must, in turn be a subset of the whitelisted actions in the manifest
* _MAY_: be sent in the same payload as one or more "Selective Disclosure" or "Authentication" requests

#### Authenticator:
* **MUST**: prompt user for approval if this is the first time encountering this Transport Authorization Request for the given manifest
* _MAY_: respond automatically if the user has previously approved an identical Transport Authorization Request for the given manifest

#### Response:
* **MUST**: include a prioritized list of vault-supported request transports
* **MUST**: include a prioritized list of vault-supported response transports
* _MAY_: be sent through one of the app-supported response transports (SHOULD favor the highest priority app-supported transport that is also vault-supported)

### Authentication Request
Allows an integrating application to request proof of a user’s possession of one or more private keys corresponding to any public keys they have disclosed. This enables passwordless authentication flows so that integrating applcations can display private data to the authenticated user.

### Selective Disclosure Request
Allows an app to request private user data (e.g., availableKeys, authorizers).

#### Request:
* **MUST**: include one or more requested attributes (e.g., availableKeys)

#### Authenticator:
* **MUST**: prompt user to approve any disclosures they have not previously approved for an identical Selective Disclosure Request
* _MAY_: respond automatically if the user has previously approved an identical Selective Disclosure Request (for the same manifest scope)

### Transaction Request
Allows an integrating application to request a user signature for a transaction.

#### Authenticator:
* **MUST**: reject the transaction request automatically if the transaction contains any actions not whitelisted in the integrating application's manifest for the given chain
* **MUST**: reject the transaction request automatically if the transaction contains any actions that have not been allowed by a previous Transport Authorization Request for the given response transport
* **MUST**: prompt the user for permission to sign if the transaction contains any actions that have been allowed by a previous Action Permission Request, without autosign privileges
* _MAY_: approve the Transaction Request automatically if the transaction contains only actions that have been allowed by a previous Action Permission Request, with autosign privileges

## Examples
### Example Request
The following example demonstrates various request formats all in one envelope. In practice, it doesn't make sense to combine all these request types in one request envelope.

```json
{
  "version": "0.0.1",
  "id": "{UUIDv4_ID}",
  "declaredDomain": "https://{siteUrl}",
  "returnUrl": "https://{siteUrl}/some-resource/resource-id?requestId={UUIDv4_ID}",
  "callbackUrl": "",
  "responseKey": "{RESPONSE_KEY}",
  "securityExclusions": {
    "addAssertToTransactions": false,
    "appMetadataIntegrity": false,
    "domainMatch": false,
    "whitelistedActions": false,
    "iconIntegrity": false,
    "relaxedContractParsing": false
  },
  "request": {
    "transportAuthorization": {
      "response": [
        {
          "type": "urlHashFragmentIdentifier",
          "actions": [
            {
              "contract": "eosio.token",
              "action": "transfer"
            },
            {
              "contract": "example.contract",
              "action": 0 // all actions
            }
          ]
          // other types may require more data, which would go here
        }
      ]
    },
    "selectiveDisclosure": {
      "disclosures": [
        {
          "type": "availableKeys"
          // other types may require more data, which would go here
        }
      ]
    },
    "transactionSignature": {
      "chainId": "{CHAIN_ID}",
      "publicKeys": [
        "{PUBLIC_KEY_1}",
        "{PUBLIC_KEY_2}"
      ],
      "abis": [
        {
          "accountName": "eosio.token",
          "abi": "{ABI_STRING}"
        }
      ],
      "transaction": {
        "signatures": ["{SIGNATURE}"],
        "compression": 0,
        "packedContextFreeData": "",
        "packedTrx": "{TRANSACTION_HEX}"
      }
    }
  }
}
```


## Request Protocol
### Request Envelope
```js
{
  version: string, // protocol semver for facilitating backwards-compatible protocol updates
  id: string, // uuidv4
  declaredDomain: string, // URL self-declared by requesting application; not trustworthy but helpful
  returnUrl: string, // URL an authenticator application should return user to after user action; must match referrerUrl domain or domain associated with the auth token
  callbackUrl: string, // for webhook response transports, must match
  responseKey: string, // public key for encrypting response
  securityExclusions: {
    addAssertToTransactions: boolean,
    appMetadataIntegrity: boolean,
    domainMatch: boolean,
    whitelistedActions: boolean,
    iconIntegrity: boolean,
    relaxedContractParsing: boolean
  },
  request: {
    transportAuthorization: {
      response: [{
        type: RequestTransports, // prioritized list of request transports supported by requesting application
      }]
    },
    selectiveDisclosure: {
      disclosures: [
        {
          type: SelectiveDisclosures
          // other types may require more data, which would go here
        }
      ]
    },
    authentication: undefined,
    transactionSignature: TransactionSignatureRequest,
  },
}
```

### _enum_ RequestTransports
* `urlQueryString`
* `serverFetch`
* `pushNotification`

### _enum_ SelectiveDisclosures
* `availableKeys`
* more forthcoming (name, email, etc.)

### TransactionSignatureRequest
```js
{
  chainId: string,
  publicKeys: string[],
  abis: HexAbi[],
  transaction: Transaction,
}
```

### HexAbi
```js
{
  accountName: string,
  abi: string, // hexadecimal
}
```

### Transaction
```js
{
  signatures: string[],
  compression: 0,
  packedContextFreeData: "",
  packedTrx: ""
}
```

## Response Protocol
```js
{
  id: string, // uuidv4
  deviceKey: string // device public key for encrypting future requests to this device
  response: {
    transportAuthorization: {
      request: RequestTransports[], // prioritized list of request transports supported by an authenticator application
      response: ResponseTransports[], // prioritized list of response transports supported by an authenticator application
      token: string, // JWT or similar token for authenticating future requests
      deviceId: string, // SE private key used only for device identification purposes
      error: ErrorResponse? // In case of error, this will be returned
    },
    selectiveDisclosure: {
      [type]: undefined,
      error: ErrorResponse? // In case of error, this alone will be returned
    },
    authentication: undefined,
    transactionSignature: {
      signedTransaction: Transaction,
      error: ErrorResponse? // In case of error, this alone will be returned
  }
}
```

### Transaction
```js
{
  signatures: string[],
  compression: 0,
  packedContextFreeData: "",
  packedTrx: ""
}
```

### ErrorResponse
```js
{
  errorCode: ErrorCodes, // one of a fixed list of error codes
  reason: string, // the reason for the error
  contextualInfo: string, // any additional contextual information useful for debugging
}
```

### _enum_ ErrorCodes
Not all error codes will be supported by all authenticators.
* `biometricsDisabled`
* `keychainError`
* `manifestError`
* `metadataError`
* `networkError`
* `parsingError`
* `resourceIntegrityError`
* `resourceRetrievalError`
* `signingError`
* `transactionError`
* `vaultError`
* `whitelistingError`
* `unexpectedError`

### _enum_ ResponseTransports
* `urlHashFragmentIdentifier`
* `webhook`

## Important

See LICENSE for copyright and license terms.  Block.one makes its contribution on a voluntary basis as a member of the EOSIO community and is not responsible for ensuring the overall performance of the software or any related applications.  We make no representation, warranty, guarantee or undertaking in respect of the software or any related documentation, whether expressed or implied, including but not limited to the warranties or merchantability, fitness for a particular purpose and noninfringement. In no event shall we be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or documentation or the use or other dealings in the software or documentation.  Any test results or performance figures are indicative and will not reflect performance under all conditions.  Any reference to any third party or third-party product, service or other resource is not an endorsement or recommendation by Block.one.  We are not responsible, and disclaim any and all responsibility and liability, for your use of or reliance on any of these resources. Third-party resources may be updated, changed or terminated at any time, so the information here may be out of date or inaccurate.
