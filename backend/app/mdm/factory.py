from __future__ import annotations

from collections.abc import Callable

from pydantic import ValidationError

from app.mdm.credentials import CredentialUnusable, JamfCredentials, decoded_credentials, refusal_sentence
from app.mdm.jamf.client import JamfClient
from app.mdm.jamf.sign_in import SIGN_INS, HeldSignIn
from app.models.schema import MdmConnection
from app.schemas.payload import MdmProvider


def get_mdm_client(connection: MdmConnection) -> JamfClient:
    """The connection's client, for one run. Jamf only (#79): the `provider` column and
    the credential-schema registry remain the seam a second provider plugs into; until one
    exists, pretending to dispatch here only hid that every caller was Jamf-shaped.

    Always a fresh client — its throttle counters are the run's own — borrowing the
    connection's held sign-in under a cache mode (#412, app.mdm.jamf.sign_in)."""
    credentials = _credentials(connection)
    build = _builder(connection, credentials)
    return build(SIGN_INS.held_for(connection, credentials, build))


def keep_sign_in(connection: MdmConnection) -> None:
    """Hold the connection's sign-in without a run to serve — and under Perpetual cache,
    start renewing it. The sign-in tick's half of #412: a connection switched to Perpetual
    cache has a token ready before its first webhook, not after it."""
    credentials = _credentials(connection)
    SIGN_INS.held_for(connection, credentials, _builder(connection, credentials))


def _credentials(connection: MdmConnection) -> JamfCredentials:
    """The connection's credential, or a refusal in words.

    This is the construction site #393 was filed against: a connection whose stored
    credentials decrypt to `{}` reached `model_validate` and the sweep recorded pydantic's
    two-paragraph report — a diagnostic that needs source code to read — into `runs.error`,
    on every tick, for as long as the connection stayed active. The validation still
    happens here, at the top of every sweep before a single request leaves; what changed is
    what comes out of it.
    """
    try:
        return JamfCredentials.model_validate(decoded_credentials(connection.credentials_encrypted))
    except ValidationError as exc:
        raise CredentialUnusable(refusal_sentence(MdmProvider(connection.provider), connection.name, exc)) from exc


def _builder(connection: MdmConnection, credentials: JamfCredentials) -> Callable[[HeldSignIn | None], JamfClient]:
    """A client factory over plain values. A held sign-in outlives the database session
    that loaded the row, and its renewal builds clients long after — an ORM attribute read
    then would be a detached-instance error, so nothing here reads the row lazily."""
    base_url = connection.base_url
    user_agent_override = connection.user_agent_override
    client_id = credentials.client_id
    client_secret = credentials.client_secret

    def build(held: HeldSignIn | None = None) -> JamfClient:
        return JamfClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            user_agent_override=user_agent_override,
            held=held,
        )

    return build
