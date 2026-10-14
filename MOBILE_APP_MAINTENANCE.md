# Mobile app maintenance

The CMS Settings page has a global **Mobile app maintenance** switch and English/
Arabic messages. It applies to all companies on both Android and iOS within the
selected environment. Turn the switch off and save to restore access. There is
no scheduled activation or automatic end time.

## Storage and administrator access

`CompAuthDb.MobileAppMaintenancePolicy` contains one row (`Id = 1`), initially
disabled, with both messages, a revision and the last administrator/time. A
database constraint prevents additional policy rows. Messages are required and
limited to 500 characters. Saves atomically check/increment the revision; stale
saves return HTTP 409 and must be reloaded before saving again.

Auth API GET/PUT `/api/settings/mobile-app-maintenance` require the authenticated
`Admin` role. Internal GET `/api/mobile-auth/app-maintenance` requires the mobile
BFF service identity and returns only enabled, messages and revision. It never
exposes the administrator identity.

## Enforcement and mobile screen

The Mobile API reads the policy through its authenticated Auth API client and
caches it for up to 30 seconds. It never serves expired policy if a fresh read
fails. Maintenance runs before force-update, device and permission checks and
returns HTTP 503 / `APP_MAINTENANCE` with bilingual policy data, `no-store` and
`Retry-After: 30`. Missing version headers cannot bypass maintenance. Login,
enrollment, heartbeat and business endpoints are blocked. Requests that already
started executing are not canceled or reversed. This does not stop background
payment/reconciliation workers or disable the web gateways.

Public GET `/api/app-status?platform=android|ios` returns `{ maintenance, update }`.
During maintenance, `update` is null; otherwise it contains the existing platform
update policy. This route, the backward-compatible `/api/app-version`, logout,
health and existing authorized web device administration remain accessible.
The status endpoint uses the existing standard rate limiter.

The app checks status before mounting login/business providers, when foregrounded
and every 60 seconds while active. An API maintenance error immediately blocks
the app. The screen displays the configured English/Arabic message and **Check
again**, without a skip or back bypass. Maintenance takes priority over force
updates. Independent policy revisions prevent stale replicas or unfinished
requests from reopening the app. Known maintenance remains visible if subsequent
checks fail. An unknown/failed startup check blocks with a separate connection
retry prompt; it is not labeled planned maintenance.

Turning maintenance off allows entry after the next successful check if the app
version is supported. This preserves stored authentication credentials, but
expired sessions can still require login when service resumes. Existing native
update prompts cannot open the store while maintenance is active; their callbacks
check the current gate state. The existing update alert behavior is retained.

## UAT-only migration and rollout

Migration `20261014082603_AddMobileAppMaintenancePolicy` creates only the policy
table and seeds one disabled policy, revision 1. Run
`./scripts/Apply-MobileAppMaintenance-Uat.ps1` from the Auth repository. The script
accepts only `10.3.3.11 / CompAuthDb`, verifies database identity/history, refuses
unrelated pending migrations, and pins Staging without changing configuration
files or printing connection credentials. Production is not migrated.

Deploy the updated Auth API first, then Mobile API/CMS, and distribute the updated
mobile app before enabling maintenance. The new app requires `/api/app-status`.
Old binaries are blocked by API enforcement but cannot show the new maintenance
screen. Maintenance starts off and is never automatically activated by migration.
Android/iOS device QA must verify startup, foreground, notification/deep-link
entry, switching off, and interactions with required updates before activation.
