// Prompt-submission ownership, transport integrity, and completion mechanics.

export function installPrivacySubmissionOwnership({
  app,
  createError,
  requireAvailable,
  onConflict,
  refresh = () => {},
}) {
  if (
    !app
    || (typeof app !== "object" && typeof app !== "function")
    || typeof createError !== "function"
    || typeof requireAvailable !== "function"
    || typeof onConflict !== "function"
    || typeof refresh !== "function"
  ) throw createError("PRIVACY_PROFILE_UNAVAILABLE");

  const api = captureDataPropertyWithoutGet(app, "api", createError);
  if (!api || (typeof api !== "object" && typeof api !== "function")) {
    throw createError("PRIVACY_PROFILE_UNAVAILABLE");
  }
  const core = Object.freeze({
    graphToPrompt: capturePrototypeMethod(app, "graphToPrompt", createError),
    appQueuePrompt: capturePrototypeMethod(app, "queuePrompt", createError),
    apiQueuePrompt: capturePrototypeMethod(api, "queuePrompt", createError),
    fetchApi: capturePrototypeMethod(api, "fetchApi", createError),
  });
  const handlers = {
    graphToPrompt: null,
    appQueuePrompt: null,
    apiQueuePrompt: null,
    fetchApi: null,
  };
  const fail = () => {
    try {
      onConflict();
    } catch (error) {
      throw error;
    }
    throw createError("PRIVACY_PROFILE_UNAVAILABLE");
  };
  const requireApp = (receiver) => {
    requireAvailable();
    if (receiver !== app || app.api !== api) {
      throw createError("PRIVACY_PROFILE_UNAVAILABLE");
    }
  };
  const requireApiReceiver = (receiver) => {
    if (receiver !== api || app.api !== api) {
      throw createError("PRIVACY_PROFILE_UNAVAILABLE");
    }
  };
  const requireApi = (receiver) => {
    requireAvailable();
    requireApiReceiver(receiver);
  };
  const guardedGraphToPrompt = async function guardedGraphToPrompt(...args) {
    refresh();
    requireApp(this);
    if (typeof handlers.graphToPrompt !== "function") fail();
    return handlers.graphToPrompt(core.graphToPrompt, this, args);
  };
  const guardedAppQueuePrompt = async function guardedAppQueuePrompt(...args) {
    refresh();
    requireApp(this);
    if (typeof handlers.appQueuePrompt !== "function") fail();
    return handlers.appQueuePrompt(core.appQueuePrompt, this, args);
  };
  const guardedApiQueuePrompt = async function guardedApiQueuePrompt(...args) {
    requireApi(this);
    if (typeof handlers.apiQueuePrompt !== "function") fail();
    return handlers.apiQueuePrompt(core.apiQueuePrompt, this, args);
  };
  const guardedFetchApi = async function guardedFetchApi(...args) {
    requireApiReceiver(this);
    const routeKind = typeof args[0] === "string"
      ? classifyPromptRoute(args[0])
      : "prompt-equivalent";
    if (routeKind === "other") {
      return core.fetchApi.apply(this, args);
    }
    requireAvailable();
    if (typeof handlers.fetchApi !== "function") fail();
    return handlers.fetchApi(core.fetchApi, this, args);
  };

  installGuardedValue(app, "api", api, fail);
  installGuardedMethod(app, "graphToPrompt", guardedGraphToPrompt, fail);
  installGuardedMethod(app, "queuePrompt", guardedAppQueuePrompt, fail);
  installGuardedMethod(api, "queuePrompt", guardedApiQueuePrompt, fail);
  installGuardedMethod(api, "fetchApi", guardedFetchApi, fail);

  return Object.freeze({
    api,
    core,
    get ready() {
      return Object.values(handlers).every((handler) => typeof handler === "function");
    },
    installHandlers(next) {
      if (
        !next
        || typeof next.graphToPrompt !== "function"
        || typeof next.appQueuePrompt !== "function"
        || typeof next.apiQueuePrompt !== "function"
        || typeof next.fetchApi !== "function"
      ) fail();
      Object.assign(handlers, next);
    },
  });
}

export function createPrivacyPromptSubmissionService({
  api,
  coreQueuePrompt,
  coreFetchApi,
  runSubmission,
  prepareSubmission,
  validateSubmission,
  revokeMinted,
  createError,
}) {
  if (
    !api
    || typeof coreQueuePrompt !== "function"
    || typeof coreFetchApi !== "function"
    || typeof runSubmission !== "function"
    || typeof prepareSubmission !== "function"
    || typeof validateSubmission !== "function"
    || typeof revokeMinted !== "function"
    || typeof createError !== "function"
  ) throw createError("PRIVACY_SNAPSHOT_OPERATION_INVALID");

  const state = {
    activePermit: null,
    submissionActive: false,
    activeController: null,
    invokingCoreQueue: false,
  };
  const error = (code) => createError(code);
  const invalidate = () => state.activeController?.abort();

  const submit = (captured, receiver, args) => {
    if (
      captured !== coreQueuePrompt
      || receiver !== api
      || state.submissionActive
      || state.invokingCoreQueue
    ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    if (
      args.length < 2
      || args.length > 3
      || typeof args[0] !== "number"
      || !Number.isFinite(args[0])
      || (args[2] !== undefined
        && (!args[2] || typeof args[2] !== "object" || Array.isArray(args[2])))
    ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");

    state.submissionActive = true;
    const controller = new AbortController();
    state.activeController = controller;
    const minted = [];
    let networkSucceeded = false;
    const submission = runSubmission(async (domain) => {
      if (state.activePermit) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
      const detached = await prepareSubmission(
        args[1],
        (reference) => minted.push(reference),
        domain,
      );
      const queueOptions = cloneQueueOptions(args[2], error);
      const expectedJson = JSON.stringify(expectedPromptBody(
        receiver,
        args[0],
        detached,
        queueOptions,
      ));
      if (typeof expectedJson !== "string") {
        throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
      }
      const permit = {
        expectedJson,
        bodyDigest: await rawSubmissionDigest(expectedJson, error),
        consumed: false,
        invalid: false,
        fetchAttempted: false,
        fetchPromise: null,
        settled: false,
        succeeded: false,
        validate: () => validateSubmission(domain),
      };
      permit.validate();
      state.activePermit = permit;
      try {
        let submitted;
        state.invokingCoreQueue = true;
        try {
          submitted = captured.apply(
            receiver,
            [args[0], detached, ...(args.length === 3 ? [queueOptions] : [])],
          );
        } finally {
          state.invokingCoreQueue = false;
        }
        const result = await submitted;
        if (permit.fetchAttempted && !permit.fetchPromise) {
          throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
        }
        const returnedBeforeFetch = permit.fetchPromise && !permit.settled;
        if (returnedBeforeFetch) controller.abort();
        if (permit.fetchPromise) await permit.fetchPromise;
        if (returnedBeforeFetch) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
        networkSucceeded = permit.succeeded
          && permit.settled
          && !permit.invalid
          && !controller.signal.aborted;
        return result;
      } finally {
        if (state.activePermit === permit) state.activePermit = null;
      }
    });
    const finalized = submission.then(
      async (result) => {
        if (!networkSucceeded) await bestEffortRevoke(minted, revokeMinted);
        return result;
      },
      async (failure) => {
        await bestEffortRevoke(minted, revokeMinted);
        throw failure;
      },
    );
    return finalized.finally(() => {
      if (state.activeController === controller) state.activeController = null;
      state.submissionActive = false;
    });
  };

  const fetchPrompt = (captured, receiver, args) => {
    if (captured !== coreFetchApi || receiver !== api || typeof args[0] !== "string") {
      throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    const route = args[0];
    const routeKind = classifyPromptRoute(route);
    if (routeKind !== "canonical") {
      if (routeKind === "prompt-equivalent") {
        throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
      }
      return captured.apply(receiver, args);
    }
    const permit = state.activePermit;
    if (!permit || permit.consumed) {
      if (permit) permit.invalid = true;
      throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    permit.fetchAttempted = true;
    permit.consumed = true;
    const options = args[1];
    if (
      args.length !== 2
      || !options
      || typeof options !== "object"
      || Array.isArray(options)
      || !hasExactOwnDataKeys(options, ["body", "headers", "method"])
      || typeof options.method !== "string"
      || options.method.toUpperCase() !== "POST"
      || typeof options.body !== "string"
      || options.body.length > 32 * 1024 * 1024
    ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    const privateHeaders = capturePromptHeaders(options.headers, error);
    const bodyString = options.body;
    let body;
    try {
      body = JSON.parse(bodyString);
    } catch {
      throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    requireExpectedPromptBodyShape(body, error);
    permit.fetchPromise = (async () => {
      try {
        const bodyDigest = await rawSubmissionDigest(bodyString, error);
        if (
          permit.invalid
          || !constantStringEqual(bodyDigest, permit.bodyDigest)
          || !constantStringEqual(bodyString, permit.expectedJson)
        ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
        permit.validate();
        if (permit.invalid) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
        const signal = state.activeController?.signal;
        if (!signal || signal.aborted) {
          throw error("PRIVACY_SNAPSHOT_TRANSACTION_STALE");
        }
        const guardedOptions = {
          method: "POST",
          headers: privateHeaders,
          body: bodyString,
          signal,
        };
        permit.validate();
        const response = await captured.apply(receiver, [route, guardedOptions]);
        permit.succeeded = true;
        return response;
      } finally {
        permit.settled = true;
      }
    })();
    permit.fetchPromise.catch(() => {});
    return permit.fetchPromise;
  };

  return Object.freeze({
    handlers: Object.freeze({
      appQueuePrompt: (captured, receiver, args) => captured.apply(receiver, args),
      apiQueuePrompt: submit,
      fetchApi: fetchPrompt,
    }),
    invalidate,
  });
}

function captureDataPropertyWithoutGet(instance, propertyName, createError) {
  let owner = instance;
  while (owner && owner !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, propertyName);
    if (descriptor) {
      if (!Object.hasOwn(descriptor, "value")) {
        throw createError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      return descriptor.value;
    }
    owner = Object.getPrototypeOf(owner);
  }
  throw createError("PRIVACY_PROFILE_UNAVAILABLE");
}

function capturePrototypeMethod(instance, methodName, createError) {
  const own = Object.getOwnPropertyDescriptor(instance, methodName);
  if (own && (own.configurable === false || !Object.hasOwn(own, "value"))) {
    throw createError("PRIVACY_PROFILE_UNAVAILABLE");
  }
  let prototype = Object.getPrototypeOf(instance);
  let method = null;
  while (prototype && prototype !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, methodName);
    if (descriptor) {
      if (typeof descriptor.value !== "function" || descriptor.get || descriptor.set) {
        throw createError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      method = descriptor.value;
      break;
    }
    prototype = Object.getPrototypeOf(prototype);
  }
  const resolved = own ? own.value : instance[methodName];
  if (typeof method !== "function" || resolved !== method) {
    throw createError("PRIVACY_PROFILE_UNAVAILABLE");
  }
  return method;
}

function installGuardedMethod(target, methodName, guardedMethod, fail) {
  const own = Object.getOwnPropertyDescriptor(target, methodName);
  Object.defineProperty(target, methodName, {
    configurable: false,
    enumerable: own?.enumerable ?? false,
    get: () => guardedMethod,
    set: fail,
  });
}

function installGuardedValue(target, propertyName, value, fail) {
  const own = Object.getOwnPropertyDescriptor(target, propertyName);
  Object.defineProperty(target, propertyName, {
    configurable: false,
    enumerable: own?.enumerable ?? false,
    get: () => value,
    set: fail,
  });
}

async function bestEffortRevoke(minted, revokeMinted) {
  const references = minted.splice(0);
  if (!references.length) return;
  try {
    await revokeMinted(references);
  } catch {
    /* TTL/session invalidation remains the final fail-closed fallback. */
  }
}

function expectedPromptBody(api, number, data, options) {
  return {
    client_id: api.clientId ?? "",
    prompt: data.output,
    ...(options?.partialExecutionTargets
      ? { partial_execution_targets: options.partialExecutionTargets }
      : {}),
    extra_data: {
      ...(api.authToken === undefined ? {} : { auth_token_comfy_org: api.authToken }),
      ...(api.apiKey === undefined ? {} : { api_key_comfy_org: api.apiKey }),
      extra_pnginfo: { workflow: data.workflow },
      ...(options?.previewMethod && options.previewMethod !== "default"
        ? { preview_method: options.previewMethod }
        : {}),
    },
    ...(number === -1 ? { front: true } : {}),
    ...(number !== 0 && number !== -1 ? { number } : {}),
  };
}

function cloneQueueOptions(options, error) {
  if (options === undefined) return undefined;
  if (
    !options
    || typeof options !== "object"
    || Array.isArray(options)
    || !Reflect.ownKeys(options).every((key) => (
      key === "partialExecutionTargets" || key === "previewMethod"
    ))
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  for (const key of Reflect.ownKeys(options)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
  }
  const previewMethod = options.previewMethod;
  if (
    previewMethod !== undefined
    && !["default", "none", "auto", "latent2rgb", "taesd"].includes(previewMethod)
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  let partialExecutionTargets;
  if (Object.hasOwn(options, "partialExecutionTargets")) {
    try {
      const serialized = JSON.stringify(options.partialExecutionTargets);
      if (typeof serialized !== "string") throw new TypeError("non-json options");
      partialExecutionTargets = JSON.parse(serialized);
    } catch {
      throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
  }
  return Object.freeze({
    ...(Object.hasOwn(options, "partialExecutionTargets")
      ? { partialExecutionTargets }
      : {}),
    ...(Object.hasOwn(options, "previewMethod") ? { previewMethod } : {}),
  });
}

function hasExactOwnDataKeys(value, expected) {
  const keys = Reflect.ownKeys(value);
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length
    || keys.some((key) => typeof key !== "string")
    || [...keys].sort().some((key, index) => key !== sortedExpected[index])
  ) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
  });
}

function capturePromptHeaders(headers, error) {
  let captured;
  try {
    if (
      typeof Headers === "function"
      && headers
      && Object.getPrototypeOf(headers) === Headers.prototype
      && Reflect.ownKeys(headers).length === 0
    ) {
      captured = new Headers(headers);
    } else if (
      headers
      && typeof headers === "object"
      && !Array.isArray(headers)
      && [Object.prototype, null].includes(Object.getPrototypeOf(headers))
    ) {
      const keys = Reflect.ownKeys(headers);
      if (keys.length !== 1 || typeof keys[0] !== "string") throw new TypeError();
      const descriptor = Object.getOwnPropertyDescriptor(headers, keys[0]);
      if (
        keys[0].toLowerCase() !== "content-type"
        || !descriptor?.enumerable
        || !Object.hasOwn(descriptor, "value")
        || typeof descriptor.value !== "string"
      ) throw new TypeError();
      captured = new Headers([[keys[0], descriptor.value]]);
    } else throw new TypeError();
  } catch {
    throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  }
  const entries = [...captured.entries()];
  if (
    entries.length !== 1
    || entries[0][0] !== "content-type"
    || entries[0][1].trim().toLowerCase() !== "application/json"
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  return captured;
}

function requireExpectedPromptBodyShape(body, error) {
  const topRequired = ["client_id", "extra_data", "prompt"];
  const topAllowed = new Set([
    ...topRequired, "partial_execution_targets", "front", "number",
  ]);
  if (
    !body
    || typeof body !== "object"
    || Array.isArray(body)
    || !topRequired.every((key) => Object.hasOwn(body, key))
    || Reflect.ownKeys(body).some((key) => typeof key !== "string" || !topAllowed.has(key))
    || !body.prompt
    || typeof body.prompt !== "object"
    || Array.isArray(body.prompt)
    || (Object.hasOwn(body, "front") && body.front !== true)
    || (Object.hasOwn(body, "front") && Object.hasOwn(body, "number"))
    || (Object.hasOwn(body, "number")
      && (typeof body.number !== "number" || !Number.isFinite(body.number)))
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  const extra = body.extra_data;
  const extraAllowed = new Set([
    "auth_token_comfy_org", "api_key_comfy_org", "extra_pnginfo", "preview_method",
  ]);
  if (
    !extra
    || typeof extra !== "object"
    || Array.isArray(extra)
    || !Object.hasOwn(extra, "extra_pnginfo")
    || Reflect.ownKeys(extra).some((key) => typeof key !== "string" || !extraAllowed.has(key))
    || (Object.hasOwn(extra, "preview_method")
      && !["none", "auto", "latent2rgb", "taesd"].includes(extra.preview_method))
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  const pngInfo = extra.extra_pnginfo;
  if (
    !pngInfo
    || typeof pngInfo !== "object"
    || Array.isArray(pngInfo)
    || !hasExactOwnDataKeys(pngInfo, ["workflow"])
    || !pngInfo.workflow
    || typeof pngInfo.workflow !== "object"
    || Array.isArray(pngInfo.workflow)
  ) throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
}

function classifyPromptRoute(route) {
  if (route === "/prompt") return "canonical";
  let candidate = route;
  for (let depth = 0; depth < 6; depth += 1) {
    if (candidateHasPromptPath(candidate)) return "prompt-equivalent";
    let decoded;
    try {
      decoded = decodeURIComponent(candidate);
    } catch {
      break;
    }
    if (decoded === candidate) break;
    candidate = decoded;
  }
  return "other";
}

function candidateHasPromptPath(candidate) {
  let parsed;
  try {
    parsed = new URL(candidate, "http://helto-privacy.invalid/");
  } catch {
    return false;
  }
  let pathname = parsed.pathname;
  for (let depth = 0; depth < 6; depth += 1) {
    const normalized = normalizePromptPath(pathname);
    if (normalized === "/prompt" || normalized === "/api/prompt") return true;
    let decoded;
    try {
      decoded = decodeURIComponent(pathname);
    } catch {
      break;
    }
    if (decoded === pathname) break;
    pathname = decoded;
  }
  return false;
}

function normalizePromptPath(pathname) {
  const segments = [];
  for (const segment of String(pathname).replaceAll("\\", "/").split("/")) {
    if (!segment || segment === ".") continue;
    if (segment === "..") segments.pop();
    else segments.push(segment);
  }
  return `/${segments.join("/")}`;
}

async function rawSubmissionDigest(value, error) {
  const cryptoApi = globalThis.crypto?.subtle;
  if (!cryptoApi || typeof cryptoApi.digest !== "function" || typeof value !== "string") {
    throw error("PRIVACY_SNAPSHOT_OPERATION_INVALID");
  }
  const digest = new Uint8Array(
    await cryptoApi.digest("SHA-256", new TextEncoder().encode(value)),
  );
  return [...digest].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function constantStringEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index % (left.length || 1)) || 0)
      ^ (right.charCodeAt(index % (right.length || 1)) || 0);
  }
  return difference === 0;
}
