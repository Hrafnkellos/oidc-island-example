# Island.is OIDC Connection Example

This is a fork of the Curity OIDC slightly modified to connect to the island.is authentication gateway.

# OpenID Connect Demo

[![Quality](https://img.shields.io/badge/quality-demo-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

This is a .NET framework demo application to explain how the OpenID Connect code flow is implemented.\
See the tutorial on the [Curity Web Site](https://curity.io/resources/learn/dotnetframework-openid-connect-client/) for further details.


## web.config
web.config is used as a configuration file for the example app. Change the values to match your system.

Name            | Type    | Mandatory | Default  | Description
----------------| ------- | :-------: | -------- | :---------------
`redirect_uri`  | string  |    ✓      |          | The redirect uri to use, must be registered for the client at the OpenID Connect server.
`client_id`     | string  |    ✓      |          | The id for the client. Used to authenticate the client against the authorization server endpoint.
`client_secret` | string  |    ✓      |          | The shared secret to use for authentication against the token endpoint.
`scope`         | string  |           | `openid` | The scopes to ask for.
`state`			| string  |           |          | ID to link auth request to callback
`code_challenge`| string  |    ✓      |          | Must be sent to the Authorization endpoint, Code challenge is paired with verifier and created from hashing the verifier value.
`code_verifier` | string  |    ✓      |          | Must be sent to the Token endpoint
`challenge_method`| string |   ✓      |          | Must be sent to the Authorization endpoint
`jwks_uri`      | URL     | if `issuer` is not set and the `openid` scope is requested          |          | The URL that points to the JWK set.
`authorization_endpoint` | URL | if `issuer` is not set     |          | The URL to the authorization_endpoint.
`token_endpoint`| URL     |    if `issuer` is not set      |          | The URL to the token_endpoint. 
`issuer`        | string  | if the `openid` scope is requested.           |          | The ID of the token issuer. This enables metadata discovery which will override the configuration set up in this file.
`base_url`      | string  |           |          | base url to be added to internal redirects. Set this to enable the client to be behind a proxy.


## Questions and Support

For questions and support, contact Curity AB:

> Curity AB
>
> info@curity.io
> https://curity.io


Copyright (C) 2016 Curity AB.
