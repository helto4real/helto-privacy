from __future__ import annotations

import asyncio

import pytest

from helto_privacy import ArtifactReference
from helto_privacy.artifact_publication import (
    ArtifactPublicationError,
    ArtifactPublicationService,
    RunScopedArtifactPublicationService,
)


class ArtifactHandle:
    def __init__(self) -> None:
        self.references: list[ArtifactReference] = []
        self.writes: list[tuple[str, str, object]] = []
        self.retired: list[tuple[str, ArtifactReference]] = []
        self.released: list[str] = []
        self.fail_write = False
        self.fail_retire_for: ArtifactReference | None = None
        self.fail_read = False
        self.retired_groups = []

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

    async def retire_group(self, artifacts):
        self.retired_groups.append(tuple(artifacts))
        for artifact_kind, reference in artifacts:
            self.retired.append((artifact_kind, reference))
        return len(artifacts)

    async def read(self, artifact_kind, reference):
        if self.fail_read:
            raise RuntimeError("synthetic read failure with product details")
        return (artifact_kind, reference)

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


def test_publication_read_validates_ownership_and_sanitizes_failures():
    first_handle = ArtifactHandle()
    second_handle = ArtifactHandle()
    first_service = ArtifactPublicationService(first_handle)
    second_service = ArtifactPublicationService(second_handle)
    publication = asyncio.run(
        first_service.write("private-video-preview", b"value")
    )

    assert asyncio.run(first_service.read(publication)) == (
        "private-video-preview",
        first_handle.references[0],
    )
    with pytest.raises(ArtifactPublicationError) as foreign:
        asyncio.run(second_service.read(publication))
    assert foreign.value.code == "PRIVACY_ARTIFACT_PUBLICATION_INVALID"

    first_handle.fail_read = True
    with pytest.raises(ArtifactPublicationError) as failed:
        asyncio.run(first_service.read(publication))
    assert "synthetic" not in str(failed.value)


def test_group_replacement_uses_distinct_owners_and_one_authority_revocation():
    handle = ArtifactHandle()
    service = ArtifactPublicationService(handle)
    first = asyncio.run(
        service.write_group("private-image-preview", [b"a", b"b"])
    )
    second = asyncio.run(
        service.write_group(
            "private-image-preview",
            [b"c", b"d"],
            replacing=first,
        )
    )

    assert len({owner for _kind, owner, _value in handle.writes}) == 4
    assert handle.retired_groups == [
        tuple(
            ("private-image-preview", reference)
            for reference in handle.references[:2]
        )
    ]
    assert all(publication.is_current is False for publication in first)
    assert all(publication.is_current is True for publication in second)
    assert asyncio.run(service.retire_group(second)) == 2
    assert all(publication.is_current is False for publication in second)


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


class ArtifactRun:
    def __init__(self, handle, owner_id):
        self.handle = handle
        self.owner_id = owner_id or "hp-owner-" + "R" * 32
        self.closed = 0

    async def write(self, artifact_kind, value):
        if self.handle.fail_write:
            raise RuntimeError("synthetic replay details")
        reference = ArtifactReference(f"hp-art-{'B' * 31}{len(self.handle.references)}")
        self.handle.references.append(reference)
        self.handle.writes.append((artifact_kind, self.owner_id, value))
        return reference

    async def close(self):
        self.closed += 1
        if self.handle.fail_close:
            raise RuntimeError("synthetic cleanup details")
        return 1


class RunArtifactHandle(ArtifactHandle):
    def __init__(self):
        super().__init__()
        self.fail_close = False
        self.reads = []
        self.runs = []

    def run(self, owner_id=None):
        run = ArtifactRun(self, owner_id)
        self.runs.append(run)
        return run

    async def read(self, artifact_kind, reference):
        self.reads.append((artifact_kind, reference))
        return b"synthetic replay payload"


def test_run_scoped_publication_reads_then_closes_exactly_once():
    handle = RunArtifactHandle()
    service = RunScopedArtifactPublicationService(handle)
    session = service.open("hp-owner-" + "O" * 32)

    publication = asyncio.run(
        session.write("save-video-replay", b"synthetic replay payload")
    )

    assert publication.to_payload() == handle.references[0].to_payload()
    assert asyncio.run(session.read(publication)) == b"synthetic replay payload"
    assert handle.writes == [
        ("save-video-replay", "hp-owner-" + "O" * 32, b"synthetic replay payload")
    ]
    assert asyncio.run(session.close()) == 1
    assert asyncio.run(session.close()) == 0
    assert handle.runs[0].closed == 1
    assert publication.is_current is False
    with pytest.raises(ArtifactPublicationError) as stale:
        asyncio.run(session.read(publication))
    assert stale.value.code == "PRIVACY_ARTIFACT_PUBLICATION_INVALID"


def test_run_scoped_failures_are_sanitized_and_close_invalidates_shells():
    handle = RunArtifactHandle()
    service = RunScopedArtifactPublicationService(handle)
    session = service.open()
    handle.fail_write = True
    with pytest.raises(ArtifactPublicationError) as failed_write:
        asyncio.run(session.write("save-video-replay", b"private"))
    assert "synthetic" not in str(failed_write.value)

    handle.fail_write = False
    publication = asyncio.run(session.write("save-video-replay", b"private"))
    handle.fail_close = True
    with pytest.raises(ArtifactPublicationError) as failed_close:
        asyncio.run(session.close())
    assert "synthetic" not in str(failed_close.value)
    assert publication.is_current is False
    assert asyncio.run(session.close()) == 0
