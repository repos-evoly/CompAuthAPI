# Mandatory mobile app updates

Policies are stored in `CompAuthDb.MobileAppUpdatePolicies`, one record per
platform (`android`, `ios`). They are global within that database/environment.

## Administration

The admin CMS Settings page reads `GET /api/settings/mobile-app-updates` and
saves one platform with `PUT /api/settings/mobile-app-updates/{platform}`.
Both routes require the existing authenticated `Admin` role. Updates require
the current revision, atomically increment it, and record the actor and UTC time.
Stale saves return 409; invalid versions, messages or store URLs return 400.

Each record includes `enabled`, `minimumVersion` (X.Y.Z), `minimumBuild`,
`storeUrl`, `messageEn`, and `messageAr`. Builds may have 1–3 numeric components.
A newer application version is supported regardless of the previous version's
build threshold; for an equal application version its build must meet the
minimum. Versions and builds are compared numerically, never alphabetically.

Android URLs must be HTTPS listings on play.google.com for
`com.bcd.companygateway`. iOS URLs must be HTTPS app listings on apps.apple.com
with a numeric store ID. The initial iOS store URL is empty because no real
listing ID was supplied. An enabled policy requires a valid store URL.

## Mobile API and app

`GET /api/mobile-auth/app-updates` is internal to the authenticated mobile BFF
service. Only public policy fields are returned, without administrator identity.
The BFF exposes `GET /api/app-version?platform=android|ios` before device/login
authentication. Its policy cache lasts at most 30 seconds; expired policy is
never served when the auth service is unavailable.

Mobile requests send `X-App-Platform`, `X-App-Version`, and `X-App-Build`, read
from the installed binary through expo-application. Outdated clients receive
HTTP 426 / `APP_UPDATE_REQUIRED` before business, login or device-enrollment
requests execute. When any policy is active, missing platform headers are also
rejected. Health, Swagger, policy reads, logout and existing authenticated web
device administration remain outside the update gate. These headers are a
compatibility check, not proof of genuine app integrity.

The mobile app checks before mounting authentication/business providers, on
foreground entry and every 60 seconds while active. Required updates show a
blocking English/Arabic screen; there is no skip option. Native store links
fall back to the configured HTTPS URL. Opening the store does not unlock the
app. Check-again/foreground checks confirm the installed version. Initial
network failure blocks access with Retry; a known update screen is retained on
subsequent failures. HTTP 426 does not clear the stored session.

Expo Go is not the application's native binary and is not suitable for testing
active version policies. Use a rebuilt development client or store build.

## UAT-only migration and rollout

Migration: `20261013134302_AddMobileAppUpdatePolicies` creates just the policy
table and seeds two **inactive** records (version 1.0.0, minimum build 0).
Nothing is activated by migrating. No existing users/settings/payment data is
modified. Production has not been migrated.

From CompAuthAPI, run `./scripts/Apply-MobileAppUpdate-Uat.ps1`. The script
rejects all targets other than 10.3.3.11 / CompAuthDb, checks actual database
identity/history, and refuses to apply unrelated pending migrations. It pins
the verified Staging connection without changing configuration files or logging
credentials. Repeat runs detect the existing migration.

Deploy the updated auth API and BFF together in UAT, publish the CMS change,
and distribute a rebuilt app containing expo-application. Rebuild native clients
after installing this dependency. The app needs the new public endpoint to start;
deploy the API changes before distributing the new app. Initially keep both
policies inactive so old binaries continue to work. Verify the real listing and
release availability on each platform before activating its minimum version
and build. Activation intentionally rejects older binaries without version
headers; those old binaries may not show the new update screen. The first release
with the checker must be distributed before enforcement is activated.

UAT and production policies are independent. This task authorizes only the UAT
migration; no deployment, production migration, store publication or push is
included. To undo a mistaken block, an authorized administrator can deactivate
or lower the affected platform's policy in the CMS without changing the other
platform. The BFF observes it within 30 seconds.

Tests cover admin authorization, validation, concurrent saves, numeric versions,
missing headers, upstream failures, policy cache expiry, startup/foreground
blocking, store fallback, retries, response races and preservation of sessions.
Physical-device checks on Android and iOS still need to verify real store
opening, installed build metadata, notification deep links and post-update entry.
