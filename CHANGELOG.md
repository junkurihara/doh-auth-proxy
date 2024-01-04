# Change Log
<!--
## 1.x.x (unreleased)

### Improvements

-

### Bugfixes

-

You should also include the user name that made the change.
-->

## 0.3.0 (Unreleased)

### Improvements

- Totally restructured and reimplemented all components
- [Breaking] Support multiple bootstrap resolvers, which requires to modify the config file.
- Periodic health check of all path candidates.
- Periodic nexthop IP address resolution via the proxy itself, bootstrap resolver is only used at the first time and fall-back.
- Periodic fetching of access token with refresh token.
- Hot reloading of configuration files, including block and override files.
- Configurable "user-agent" as whatever you like.

## 0.2.0

### Improvements

- Docker UID:GID: Update Dockerfiles to allow arbitrary UID and GID (non-root users) for rpxy. Now they can be set as you like by specifying through env vars.
- Refactor: Various minor improvements
- Change inner structure of proxy's supplemental services other than UDP/TCP acceptors.

## 0.1.5 (Jun. 6, 2022)

### Improvements

- Update override-list format to use individual lines for representing multiple matching for a name, i.e., (name, IPv4) and (name, IPv6).
- Updates required args to run. Now it works without args.

### Bugfixes

- Fix matching rule for blocklist and override-list

## 0.1.4 (May 17, 2022)
### Improvements

- Used a forked version of Cloudflare's `odoh-rs` library for frequently maintenance by @junkurihara: [https://github.com/junkurihara/odoh-rs.git](https://github.com/junkurihara/odoh-rs.git)
- Domain-based filtering and domain-override


## 0.1.3 (Apr. 16, 2022)

### Improvements

- Add on-memory DNS cache to make query-response faster.
- Refactor to merge some global variables in `Arc`s into `Arc<Globals>`.
- Update deps

## 0.1.2 (Apr. 8, 2022)

### Improvements

- Feature: add health check sending a ping to each (O)DoH target when (re)bootstrap of client instances
