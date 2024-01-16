# Magiavventure - Lib jwt

This library takes care of managing the security of the endpoints with spring security and the management of the jwt.

## Configuration

The properties exposed to configure this project are:

```properties
logging.level.app.magiavventure="string"                                                # Logging level package magiavventure
magiavventure.lib.common.errors.errors-messages.{error-key}.code="string"               # The exception key error code
magiavventure.lib.common.errors.errors-messages.{error-key}.message="string"            # The exception key error message
magiavventure.lib.common.errors.errors-messages.{error-key}.description="string"        # The exception key error description
magiavventure.lib.common.errors.errors-messages.{error-key}.status=integer              # The exception key error status
magiavventure.lib.jwt.secret="string"                                                   # The secret for token generation and parse
magiavventure.lib.jwt.validity=integer                                                  # The validity of the token in minutes
magiavventure.lib.jwt.header="string"                                                   # The header to extract for the token
magiavventure.lib.jwt.endpoints.[n].path="string"                                       # The path to secure
magiavventure.lib.jwt.endpoints.[n].roles="string"                                      # Authorized roles
magiavventure.lib.jwt.endpoints.[n].authenticated=boolean                               # Whether authentication is required for the path or not
magiavventure.lib.jwt.excludedEndpoints="string"                                        # Endpoints excluded for token check
```


## Error message map
The error message map is a basic system for return the specific message in the error response,
the configuration path at the moment is only for one branch **errors-messages**.
This branch setting a specific error message to **it.magiavventure.common.error.MagiavventureException**