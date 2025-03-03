# Log Messages for Portal Token Module

All messages follow the format: PortalToken-[identifier]: [message]

## INFO Level (001-099)

| ID | Component | Message | Description |
|----|-----------|---------|-------------|
| PortalToken-001 | JWKS | Initializing JWKS lookup, jwks-endpoint='%s', refresh-interval='%s', issuer='%s' | Logged during startup when configuring JWKS-based token validation |

## WARN Level (100-199)

| ID | Component | Message | Description |
|----|-----------|---------|-------------|
| PortalToken-100 | TOKEN | Token exceeds maximum size limit of %s bytes, token will be rejected | Logged when a token is rejected due to size constraints |
| PortalToken-101 | TOKEN | The given token was empty, request will be rejected | Logged when an empty or null token is provided |
| PortalToken-102 | TOKEN | Unable to parse token due to ParseException: %s | Logged when token parsing fails due to format or content issues |
