Microsoft Entra ID SSO Plugin for Fess
[![Java CI with Maven](https://github.com/codelibs/fess-sso-entraid/actions/workflows/maven.yml/badge.svg)](https://github.com/codelibs/fess-sso-entraid/actions/workflows/maven.yml)
======================================

Microsoft Entra ID single sign-on for [Fess](https://github.com/codelibs/fess).

This plugin provides the **SSO authenticator** behind `sso.type=entraid`: Fess acts as an OAuth
2.0 / OpenID Connect confidential client, sends the browser to Entra ID, exchanges the
authorization code for a token, and then resolves the user's group and role memberships through
Microsoft Graph so that role-based search applies to them.

It was part of the Fess distribution until 15.9. It moved here with MSAL4J and the Nimbus OAuth
2.0 SDK, which are about 2.5 MiB of jars that most installations never use.

## Installation

```
$ bin/fess-setup install plugin fess-sso-entraid
```

Or download the jar from [maven.codelibs.org](https://maven.codelibs.org/org/codelibs/fess/fess-sso-entraid/)
and put it in `app/WEB-INF/plugin`. Restart Fess afterwards: the components this plugin
contributes are read when the DI container is built.

## Configuration

Set these on the General page of the administration screen, or write them to
`app/WEB-INF/conf/system.properties`. A `-Dfess.system.<key>=...` on the JVM command line also
works, but only for a key the file does not hold: the file wins over the system property.
None of these are `fess_config.properties` keys.

First select this authenticator:

| Key | Value |
| --- | --- |
| `sso.type` | `entraid` |

`aad` is accepted as well: `SsoManager` maps the legacy value to `entraid`.

Then configure the application registered in Entra ID:

| Key | Value |
| --- | --- |
| `entraid.tenant` | the tenant, for example `contoso.onmicrosoft.com` (required) |
| `entraid.client.id` | the application (client) ID (required) |
| `entraid.client.secret` | the client secret value (required) |
| `entraid.reply.url` | the redirect URI; the request URL is used when blank |
| `entraid.authority` | the authorization server (default `https://login.microsoftonline.com/`) |
| `entraid.response.mode` | `query` (the default) or `form_post` |
| `entraid.state.ttl` | how long an unanswered authorization request stays usable, in seconds (default `3600`) |
| `entraid.default.groups` | groups applied to every Entra ID user, comma-separated |
| `entraid.default.roles` | roles applied to every Entra ID user, comma-separated |
| `entraid.permission.fields` | group and role fields to add as permission values on top of the object ID, comma-separated (default `mail`) |
| `entraid.use.ds` | when `true` (the default), also add the local part of a `name@domain` permission value |

Each key has a legacy `aad.*` spelling — `aad.tenant`, `aad.client.id` and so on — that is read
when the `entraid.*` one holds no value.

Four things are worth knowing before the first login:

* **`entraid.state.ttl` has to be positive.** A state that expires immediately is dropped before
  the user can finish signing in at Microsoft, and the callback then reports only "could not
  validate state", naming neither this setting nor the reason — no login on the server can
  succeed. A non-positive value is therefore refused: the default of 3600 seconds is used instead
  and a warning naming the key is logged.
* **`form_post` needs HTTPS.** Fess ships `tomcat.sameSiteCookies = lax`, and a Lax cookie is not
  sent on the cross-site POST that `form_post` produces, so the callback arrives without
  `JSESSIONID` and the login loops. Selecting `form_post` therefore also means setting
  `tomcat.sameSiteCookies = none`, and a `None` cookie requires the `Secure` attribute — so Fess
  has to be served over HTTPS.
* **A crawler has to write the object ID.** The user-level permission this plugin grants is built
  from the `oid` claim of the ID token, which is how Microsoft Graph names a user. A document ACL
  that names the user any other way is not matched.
* **`User.Read` is not optional.** Memberships are read from `/me/memberOf`, which
  `Group.Read.All` does not authorize. Grant `User.Read` (and `GroupMember.Read.All`, or
  `Group.Read.All` / `Directory.Read.All`, for the parent-group walk) on the app registration.

See the [Entra ID SSO documentation](https://fess.codelibs.org/stable/config/sso-entraid.html)
for the app registration itself.

## Version

| Fess | Plugin |
| --- | --- |
| 15.9.x | 15.9.x |

Match the minor version. Installing this plugin into Fess 15.8 or earlier breaks SSO with a 500:
those versions register `entraidAuthenticator` in their own `fess_sso++.xml`, and a second
registration under the same name from this plugin makes `getComponent()` fail with
`TooManyRegistrationComponentException`.

## How it plugs in

Nothing here is wired by class name from Fess. The plugin ships one additive LastaDi file that
Fess merges from every jar on the class path:

* `fess_sso++.xml` registers `entraidAuthenticator`. `SsoManager.getAuthenticator()` resolves an
  authenticator as `<sso.type>Authenticator`, so the component name is what makes
  `sso.type=entraid` resolve. It is a singleton, because the authenticator registers that
  instance with `ssoManager` from its `init()`.

The `SsoAuthenticator` interface, `SsoManager`, `SsoAction` and the SSO section of the
administration screen remain in Fess; only this authenticator, the credential it hands to
`FessLoginAssist`, and the libraries they compile against ship here. MSAL4J and the Nimbus SDK
are shaded in without relocation: MSAL4J reads its own class names out of configuration and
resource files, and both this jar and MSAL4J name the Nimbus SDK.
