# Target privacy interface designs

## Prototype question

Which consumer-facing interface gives `helto-privacy` maximum depth and
locality while leaving only product facts, transformations, and domain behavior
in the four consumer packs?

This is a planning artifact, not production code. All three designs must obey
the same fixed contract:

- Private is the canonical default. The server resolves effective privacy mode,
  and a request or local declaration cannot weaken a privacy floor.
- Consumer registrations are immutable, atomic, order-independent, and checked
  against one machine-readable browser/server contract.
- Missing packages, capabilities, registrations, adapters, keystores, keys, or
  lifecycle state block private operations.
- Consumers never receive keys, token semantics, general decrypt functions,
  lease/grant issuers, shell builders, error mappers, or cleanup policy.
- New writes use only current formats. Legacy readers are exact, read-only,
  isolated, observable, and removable.
- The shared module owns locked record shells, authorized reveals, artifacts,
  leases, privacy snapshots, serialization barriers, execution grants,
  transitions, recovery, authorization, sanitized failures, and shared UI.

The real dependency seams are:

- In-process policy and state machines remain inside the shared module.
- Filesystem, keystore, artifact, clock, and cleanup dependencies use internal
  local-substitutable adapters.
- Browser-to-server HTTP is remote-but-owned, with aiohttp/Fetch production
  adapters and an in-memory test adapter.
- ComfyUI lifecycle, product state locations, record stores, payload encoders,
  allowed-root checks, semantic projections, and product dispatchers are narrow
  external or consumer adapters.

## Design 1 — minimal manifest plus command port

This design minimizes callable surface area:

```python
privacy = register(ConsumerSpec(...))
result = privacy.perform(TypedIntent(...))
```

```javascript
const privacy = await connectPrivacy(UiSpec)
await privacy.perform(browserIntent)
```

`ConsumerSpec` is a closed set of scope, protected-state, record, artifact,
workflow, and protected-operation bindings. `TypedIntent` is a closed union of
mode resolution, transition, persistence, reveal, artifact, snapshot, dispatch,
and authorization operations. It is not a stringly command bus and has no
consumer-defined custom operation.

Representative calls:

```python
# Utils selector and durable mask
privacy.perform(PrepareSnapshot("selector"))
privacy.perform(WriteArtifact("selector-mask", owner, mask_bytes))

# AIO private prompt library
shells = privacy.perform(ListRecords("ideogram-prompts"))
prompt = privacy.perform(RevealRecord("ideogram-prompts", record_id, "use"))

# Director thumbnail
ref = privacy.perform(WriteArtifact("thumbnail", owner, image_bytes))
lease = privacy.perform(IssueArtifactLease(ref, "preview"))

# Smart Prompt execution
snapshot = privacy.perform(PrepareSnapshot("prompt-library"))
result = privacy.perform(DispatchSnapshot(snapshot.grant, context))
```

The module hides every policy and lifecycle step behind `perform`. This gives
high leverage per method and makes atomic registration easy. Its weakness is
discoverability: the intent union becomes a second large interface concealed
behind one method. If exceptional cases lead to generic payloads or custom
intents, the module becomes a command router instead of a deep privacy module.

## Design 2 — typed capability graph

This design maximizes extension and introspection:

```python
draft = privacy_hub.begin(ConsumerManifest(...))
draft.bind("director.timeline", TimelineFieldAdapter())
draft.bind("director.project-store", ProjectStoreAdapter())
director = draft.activate()

timeline = director.field("timeline.state")
projects = director.records("timeline-project")
thumbnail = director.artifacts("thumbnail-cache")
execution = director.execution("timeline-render")
```

The manifest is a versioned declaration graph containing mode scopes,
protected fields, legacy bindings, record kinds, artifact kinds, plaintext
derivatives, execution kinds, and domain operations. Activation compiles a new
immutable registry generation, rejects cycles or incomplete slots, and returns
granular typed handles.

Representative registrations:

```python
# Utils
draft.bind("utils.selector-fields", SelectorFieldAdapter())
draft.bind("utils.selector-mask", MaskPayloadAdapter())

# AIO
draft.bind("aio.generate-prompts", AioPromptFieldAdapter())
draft.bind("aio.ideogram-store", IdeogramPromptStore())

# Director
draft.bind("director.timeline", TimelineFieldAdapter())
draft.bind("director.allowed-media", DirectorAllowedRootAdapter())

# Smart Prompt
draft.bind("spm.state", SmartPromptStateAdapter())
draft.bind("spm.semantic-projection", SmartPromptSemanticProjection())
draft.bind("spm.dispatch", SmartPromptDispatcher())
```

The browser loads the same declaration, binds DOM/editor adapters by slot, and
negotiates its manifest fingerprint against the server before it receives field,
mode, execution, and UI handles.

This is the most auditable and extensible shape. It exposes capability
relationships precisely and makes late registration naturally order-independent.
Its cost is interface breadth: consumers must understand the declaration graph,
capability versions, adapter slots, activation states, and handle families.
Cross-language slot drift and capability-version proliferation become permanent
risks. Much of that flexibility is unnecessary during the coordinated cutover.

## Design 3 — atomic pack profile plus bound façade

This design treats the shared privacy contract as one coherent suite. A consumer
declares its privacy-bearing product state once and receives typed handles for
the capabilities it actually declared:

```python
pack = install(
    PackProfile(
        id="helto.smart-prompt",
        contract=PRIVACY_CONTRACT_V2,
        workflow=(WorkflowState(...),),
    ),
    adapters=PackAdapters(workflow={"prompt-library": smart_prompt_adapter}),
)

workflow = pack.workflow("prompt-library")
```

The fixed profile vocabulary is small:

```python
PackProfile(
    id,
    distribution,
    contract,
    scopes=(PrivacyScope(...),),
    workflow=(WorkflowState(...),),
    records=(RecordLibrary(...),),
    artifacts=(ArtifactKind(...),),
    protected_routes=(ProtectedRoute(...),),
)
```

`install()` validates and fingerprints the complete profile atomically, records
it even when PromptServer is not ready, attaches shared hooks later, and returns
`BoundPrivacyPack`. Identical registration is idempotent; conflicting or
incomplete registration blocks the pack. The profile cannot configure the
private base default, crypto, policy precedence, error mapping, shell shape,
lease/grant rules, or cleanup semantics.

Representative profiles and calls:

```python
# Utils: selector fields plus durable mask artifact
utils = install(PackProfile(
    id="helto.utils",
    contract=PRIVACY_CONTRACT_V2,
    workflow=(WorkflowState(
        id="selector",
        nodes=(NodeBinding(
            types=("HeltoMultiImageSelector",),
            mode=PropertyMode("privacyMode", legacy_bool=True),
            fields=(
                PrivateField("selected_images", Widget(), current_schema, "[]"),
                PrivateField("edited_masks", Widget(), current_schema, "{}"),
                PrivateField("edited_bboxes", Widget(), current_schema, "{}"),
            ),
        ),),
    ),),
    artifacts=(ArtifactKind(
        "selector-mask", "selector-mask", 1, "durable-adjunct", ("use",)
    ),),
), adapters=UtilsPrivacyAdapters(...))

mask_ref = await utils.artifacts("selector-mask").write(owner, mask_bytes)

# AIO: prompts plus private record library
aio = install(PackProfile(
    id="helto.aio-image-generation",
    contract=PRIVACY_CONTRACT_V2,
    workflow=(WorkflowState(id="generate-prompts", ...),),
    records=(RecordLibrary(
        "ideogram-prompts",
        kind="ideogram-prompt",
        current_schema=record_schema,
        fixed_private_label="Private record",
        safe_projection=(),
    ),),
), adapters=AioPrivacyAdapters(records={"ideogram-prompts": prompt_store}))

shells = await aio.records("ideogram-prompts").list(query)
prompt = await aio.records("ideogram-prompts").reveal(request, record_id, "use")

# Director: global floor plus managed thumbnails
director = install(PackProfile(
    id="helto.director",
    contract=PRIVACY_CONTRACT_V2,
    scopes=(PrivacyScope(
        "project", mode=SettingMode("privacy.mode", legacy_bool=True), private_is_floor=True
    ),),
    workflow=(WorkflowState(id="timeline", ...),),
    records=(RecordLibrary("projects", "director-project", project_schema, "Private record"),),
    artifacts=(ArtifactKind(
        "thumbnail", "timeline-thumbnail", 1, "regenerable-cache", ("preview",)
    ),),
), adapters=DirectorPrivacyAdapters(...))

thumbnail = director.artifacts("thumbnail")
ref = await thumbnail.write(owner, image_bytes)
lease = await thumbnail.lease(request, ref, "preview")

# Smart Prompt: legacy read, snapshot, grant, dispatch-time reveal
smart = install(PackProfile(
    id="helto.smart-prompt",
    contract=PRIVACY_CONTRACT_V2,
    workflow=(WorkflowState(
        id="prompt-library",
        nodes=(NodeBinding(
            types=("SmartPromptManager",),
            mode=PropertyMode("privacyMode", legacy_bool=True),
            fields=(PrivateField(
                "spm_data", Widget(), current_schema, {},
                legacy_readers=("smart-prompt-v1",), execution=True,
            ),),
        ),),
        semantic_execution=AdapterProjection("smart-prompt-runtime"),
    ),),
), adapters=SmartPromptPrivacyAdapters(...))

with smart.workflow("prompt-library").resolve_execution(protected_input, context) as dispatch:
    result = run_product_logic(dispatch.value)
```

The dispatch context couples validation, reveal, product invocation lifetime,
and plaintext cleanup. Consumers cannot retain a reusable decrypt function.

The browser has one connection entry point:

```javascript
const privacy = await connectPrivacyPack({
  app,
  packId: "helto.director",
  contract: PRIVACY_CONTRACT_V2,
  adapters: {
    "timeline-runtime": {
      normalize: readTimelineState,
      apply: applyTimelineState,
      clear: clearTimelinePlaintext,
    },
  },
})

privacy.mountModeControl(node, { afterWidget: "privacy_mode" })
const url = await privacy.mediaUrl(thumbnailRef, { operation: "preview" })
```

Connection verifies the exact contract suite and profile digest, installs the
shared ComfyUI lifecycle hooks, reconciles existing and future nodes, mounts the
shared declared/effective mode UI, owns recovery and unlock dialogs, and
coordinates save/queue barriers. Consumers select only a mount point and supply
editor adapters.

## Comparison and recommendation

The minimal command port has the smallest nominal interface, but most of its
complexity moves into `ConsumerSpec` and the intent union. That reduces
discoverability and makes misuse easier to hide in a generic `perform` call. It
is a valuable lower bound, not the strongest production seam.

The capability graph is the most flexible and most explicit. It would be the
best choice if third-party packs needed to assemble arbitrary subsets of a
long-lived privacy platform. That is not the current destination: the five
repositories are moving through one coordinated cutover under one strict
policy suite. The graph exposes more concepts than these consumers need and
creates extra version and slot-drift surfaces.

The atomic pack profile gives the best depth. One declaration activates the
whole strict lifecycle, while bound workflow, record, and artifact handles keep
operations typed and discoverable. Product variation crosses real adapter seams:
record stores, editor normalization, payload encoding, allowed roots, semantic
execution projection, and product dispatch. Policy variation is not an adapter.

Recommended design: **Design 3, atomic pack profile plus bound façade**, with
two safeguards borrowed from the other designs:

1. Use the capability graph's immutable fingerprint and exact browser/server
   contract attestation internally, but expose one fixed V2 suite rather than
   consumer-negotiated capability assembly.
2. Keep the minimal design's closed resource vocabulary. New privacy behavior
   must become a typed shared profile kind or remain outside the privacy module;
   there is no generic custom operation escape hatch.

The deletion test is strong: removing `helto-privacy` would force mode policy,
transitions, authorization, recovery, serialization, records, artifacts,
leases, grants, redaction, and UI behavior back into every pack. Removing one
consumer profile removes only that pack's product facts and adapters.
