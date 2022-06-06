# Change Log
<!--
## 1.x.x (unreleased)

### Improvements

-

### Bugfixes

-

You should also include the user name that made the change.
-->

## 0.1.x (unreleased)
### Improvements

- Update override-list format to use individual lines for representing multiple matching for a name, i.e., (name, IPv4) and (name, IPv6).

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
