from __future__ import annotations

import asyncio

import pytest

from helto_privacy import ArtifactReference
from helto_privacy.artifact_publication import (
    ArtifactPublicationError,
    ArtifactPublicationService,
)


class ArtifactHandle:
    def __init__(self) -> None:
        self.references: list[ArtifactReference] = []
        self.writes: list[tuple[str, str, object]] = []
        self.retired: list[tuple[str, ArtifactReference]] = []
        self.released: list[str] = []
        self.fail_write = False
        self.fail_retire_for: ArtifactReference | None = None

    async def write(self, artifact_kind, owner_id, value):
        if self.fail_write:
            raise RuntimeError("synthetic write failure with product details")
        index = len(self.references)
        reference = ArtifactReference(f"hp-art-{'A' * 31}{index}")
        self.references.append(reference)
        self.writes.append((artifact_kind, owner_id, value))
        return reference

    async def retire(self, artifact_kind, reference):
        self.retired.append((artifact_kind, reference))
        if reference == self.fail_retire_for:
            raise RuntimeError("synthetic retirement failure with product details")
        return 1

    async def release_owner(self, owner_id):
        self.released.append(owner_id)
        return 1

    async def sweep(self):
        return "synthetic-sweep"


def test_publication_reference_contains_no_product_data_or_paths():
    handle = ArtifactHandle()
    service = ArtifactPublicationService(handle)

    publication = asyncio.run(
        service.write(
            "private-image-preview",
            b"synthetic-private-image",
            owner_id="owner",
        )
    )

    payload = publication.to_payload()
    assert payload == handle.references[0].to_payload()
    serialized = str(payload)
    assert "synthetic-private-image" not in serialized
    assert "token" not in serialized.lower()
    assert "filename" not in serialized.lower()
    assert "path" not in serialized.lower()
    assert "hp-art-" not in repr(publication)


def test_replacement_retires_previous_reference_and_invalidates_its_shell():
    handle = ArtifactHandle()
    service = ArtifactPublicationService(handle)
    first = asyncio.run(
        service.write("private-video-preview", b"first", owner_id="owner")
    )

    second = asyncio.run(
        service.write(
            "private-video-preview",
            b"second",
            owner_id="owner",
            replacing=first,
        )
    )

    assert handle.retired == [("private-video-preview", handle.references[0])]
    assert first.is_current is False
    assert second.is_current is True


def test_failures_are_sanitized_and_failed_replacement_retires_new_reference():
    handle = ArtifactHandle()
    service = ArtifactPublicationService(handle)
    handle.fail_write = True
    with pytest.raises(ArtifactPublicationError) as failed_write:
        asyncio.run(service.write("private-image-preview", b"private"))
    assert "synthetic" not in str(failed_write.value)

    handle.fail_write = False
    first = asyncio.run(service.write("private-video-preview", b"first"))
    handle.fail_retire_for = first._reference
    with pytest.raises(ArtifactPublicationError) as failed_replacement:
        asyncio.run(
            service.write(
                "private-video-preview",
                b"second",
                replacing=first,
            )
        )
    assert "synthetic" not in str(failed_replacement.value)
    assert first.is_current is False
    assert handle.retired == [
        ("private-video-preview", handle.references[0]),
        ("private-video-preview", handle.references[1]),
    ]


def test_multi_kind_service_releases_and_sweeps_resource_once():
    handle = ArtifactHandle()
    service = ArtifactPublicationService(handle)
    image = asyncio.run(
        service.write("private-image-preview", b"image", owner_id="owner")
    )
    video = asyncio.run(
        service.write("private-video-preview", b"video", owner_id="owner")
    )

    assert asyncio.run(service.release_owner("owner")) == 1
    assert handle.released == ["owner"]
    assert image.is_current is False
    assert video.is_current is False
    assert asyncio.run(service.startup_recover()) == "synthetic-sweep"
