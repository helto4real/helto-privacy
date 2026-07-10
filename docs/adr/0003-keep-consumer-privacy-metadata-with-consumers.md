# Keep consumer privacy metadata with consumer packs

`helto-privacy` owns the versioned registration contract, validation, registry,
lifecycle, privacy behavior, and generic UI, while each consumer pack owns a
thin registration of its product-specific privacy metadata and adapters. This
keeps product facts beside the product code, avoids forcing shared-package
releases for consumer-only changes, and avoids the two sources of truth created
by a hybrid central catalog plus consumer callbacks.
