"""Prove atomic grant bounds, retries, replica sharing and restore invalidation."""

import asyncio
import base64
from datetime import UTC, datetime, timedelta
import secrets
from uuid import UUID, uuid4

from cloudcoil.apimachinery import ObjectMeta
from cloudcoil.client import AsyncAPIClient
import httpx
import pytest

from opendefence_integration_tak.delivery import DeliveryError
from opendefence_integration_tak.grants import Grant, GrantDocument, SecretGrantStore
from opendefence_integration_tak.resources import Secret
from tests.kubernetes import KubernetesFixture


def sample_grant(user_id: UUID | None = None) -> Grant:
    now = datetime.now(UTC)
    return Grant(
        id=secrets.token_urlsafe(16),
        user_id=user_id or uuid4(),
        profile_id="atak",
        credential_id="tak-1",
        authorizing_id="main-1",
        token_hash="0" * 64,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        target_revision="revision",
    )


def storage() -> tuple[SecretGrantStore, KubernetesFixture]:
    fixture = KubernetesFixture()
    fixture.put(Secret(metadata=ObjectMeta(name="tak-download-grants", namespace="tak")), "secrets")
    return SecretGrantStore(fixture.async_client(Secret, "secrets")), fixture


def test_compare_and_swap_and_replicas() -> None:
    store, fixture = storage()
    grant = sample_grant()
    fixture.conflicts = 1
    asyncio.run(store.create(grant, grant.created_at))
    replica = SecretGrantStore(fixture.async_client(Secret, "secrets"))
    assert asyncio.run(replica.get(grant.id)) == grant
    other = sample_grant(grant.user_id)
    fixture.conflicts = 1
    asyncio.run(replica.create(other, other.created_at))
    assert asyncio.run(store.get(grant.id)) == grant
    assert asyncio.run(store.get(other.id)) == other
    fixture.conflicts = 1
    asyncio.run(store.delete(grant.id, grant.user_id))
    assert asyncio.run(replica.get(grant.id)) is None
    assert asyncio.run(replica.get(other.id)) == other


def test_replica_race_cannot_exceed_owner_limit() -> None:
    store, fixture = storage()
    user_id = uuid4()
    for _ in range(7):
        grant = sample_grant(user_id)
        asyncio.run(store.create(grant, grant.created_at))

    async def race() -> None:
        arrived = 0
        barrier = asyncio.Event()
        conflicts = 0

        async def handle(request: httpx.Request) -> httpx.Response:
            nonlocal arrived, conflicts
            response = fixture.handle(request)
            if request.method == "GET":
                arrived += 1
                if arrived <= 2:
                    if arrived == 2:
                        barrier.set()
                    await barrier.wait()
            if response.status_code == 409:
                conflicts += 1
            return response

        replicas = [
            SecretGrantStore(
                AsyncAPIClient(
                    "v1",
                    Secret,
                    "secrets",
                    [],
                    "tak",
                    True,
                    httpx.AsyncClient(base_url="https://kubernetes.fixture", transport=httpx.MockTransport(handle)),
                )
            )
            for _ in range(2)
        ]
        first, second = sample_grant(user_id), sample_grant(user_id)
        results = await asyncio.gather(
            replicas[0].create(first, first.created_at),
            replicas[1].create(second, second.created_at),
            return_exceptions=True,
        )
        assert results.count(None) == 1
        error = next(item for item in results if item is not None)
        assert isinstance(error, DeliveryError) and error.status == 429
        assert conflicts == 1
        stored = await asyncio.gather(store.get(first.id), store.get(second.id))
        assert sum(item is not None for item in stored) == 1

    asyncio.run(race())


def test_retry_exhaustion_and_duplicate_id() -> None:
    store, fixture = storage()
    grant = sample_grant()
    fixture.conflicts = 4
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.create(grant, grant.created_at))
    asyncio.run(store.create(grant, grant.created_at))
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.create(grant, grant.created_at))
    fixture.conflicts = 4
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.delete(grant.id, grant.user_id))


def test_expiry_cleanup_during_create() -> None:
    store, _ = storage()
    grant = sample_grant()
    asyncio.run(store.create(grant, grant.created_at))
    later = grant.model_copy(
        update={
            "id": secrets.token_urlsafe(16),
            "created_at": grant.expires_at,
            "expires_at": grant.expires_at + timedelta(minutes=5),
        }
    )
    asyncio.run(store.create(later, later.created_at))
    assert asyncio.run(store.get(grant.id)) is None
    assert asyncio.run(store.get(later.id)) == later


def test_restore_does_not_restore_capabilities() -> None:
    store, fixture = storage()
    grant = sample_grant()
    asyncio.run(store.create(grant, grant.created_at))
    secret = next(iter(fixture.objects.values()))
    assert secret.metadata is not None
    secret.metadata.uid = "new-incarnation"
    assert asyncio.run(store.get(grant.id)) is None
    successor = sample_grant()
    asyncio.run(store.create(successor, successor.created_at))
    assert asyncio.run(store.get(successor.id)) == successor


@pytest.mark.parametrize(
    "bad",
    ["not base64!", base64.b64encode(b"{}").decode(), "A" * 800_001],
    ids=["invalid-base64", "invalid-json", "oversized-data"],
)
def test_corrupt_storage_fails_closed(bad: str) -> None:
    store, fixture = storage()
    secret = next(iter(fixture.objects.values()))
    assert isinstance(secret, Secret)
    secret.data["grants.json"] = bad
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.get("A" * 22))


def test_missing_secret_and_metadata_fail_closed() -> None:
    store, fixture = storage()
    fixture.objects.clear()
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.get("A" * 22))
    fixture.put(Secret(metadata=ObjectMeta(name="tak-download-grants", namespace="tak")), "secrets")
    secret = next(iter(fixture.objects.values()))
    assert secret.metadata is not None
    secret.metadata.uid = None
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.get("A" * 22))


def test_foreign_delete_and_write_failure() -> None:
    store, fixture = storage()
    grant = sample_grant()
    asyncio.run(store.create(grant, grant.created_at))
    with pytest.raises(DeliveryError) as error:
        asyncio.run(store.delete(grant.id, uuid4()))
    assert error.value.status == 404
    fixture.failures = True
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.delete(grant.id, grant.user_id))
    with pytest.raises(DeliveryError, match="grant-store-unavailable"):
        asyncio.run(store.create(sample_grant(), datetime.now(UTC)))


def test_global_bound_and_document_size() -> None:
    store, fixture = storage()
    secret = next(iter(fixture.objects.values()))
    assert isinstance(secret, Secret) and secret.metadata and secret.metadata.uid
    document = GrantDocument(store_uid=secret.metadata.uid)
    for _ in range(256):
        grant = sample_grant()
        document.grants[grant.id] = grant
    secret.data["grants.json"] = base64.b64encode(document.model_dump_json().encode()).decode()
    grant = sample_grant()
    with pytest.raises(DeliveryError) as error:
        asyncio.run(store.create(grant, grant.created_at))
    assert error.value.status == 429
    secret.data.clear()
    enormous = sample_grant().model_copy(update={"target_revision": "a" * 600_001})
    with pytest.raises(DeliveryError) as error:
        asyncio.run(store.create(enormous, enormous.created_at))
    assert error.value.status == 429
