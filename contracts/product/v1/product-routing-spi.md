# Persisted Product routing adapter

`StoredRoutePlanner` implements the existing `model.routing.v1` consumer seam:

```text
plan(normalizedRequest) -> ordered RouteTarget[]
```

It reads active routes from the Exchange Product store, matches `modelPattern`,
and returns opaque `targetBindingId` values. A delegating resolver intercepts
only `model.routing.v1`; all `model.provider.v1` resolution continues through the
canonical Platform resolver. The adapter neither imports plugin packages nor
owns provider lifecycle.

`build_gateway_from_store(store, endpoint_id, delegate, ...)` is the public
composition seam for one selected `GatewayEndpoint`. The caller retains the
store, Platform resolver, direct Plugin client, and HTTP transport lifecycles,
so the helper remains a pure wiring operation rather than another authority.
