# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""Form data normalization and the consent-page ("presentation") view model.

:func:`form_formatter` turns the flat HTML form submitted by the user into
the nested attribute dict stored as the session's user data.
:func:`presentation_formatter` builds, per requested credential, the data
shown to the user before issuance.
"""

from __future__ import annotations

import base64
import datetime
import json
import re
from typing import Any, Dict, Iterable, List

from app.core.constants import ConfService as cfgserv
from app.core.state import oidc_metadata
from app.services.attributes import getAttributesForm, getAttributesForm2
from app.utils.dates import calculate_age, format_date, to_rfc3339

_KEY_PARTS = re.compile(r"([^\[\]]+)")
_SKIPPED_FORM_KEYS = ("proceed", "Cancelled", "NumberCategories")
_IMAGE_FIELDS = (
    "portrait",
    "image",
    "picture",
    "signature_usual_mark",
    "signature_usual_mark_issuing_officer",
)
#: Fields stored as base64url and shown to the user as standard base64.
_DISPLAY_DECODED_FIELDS = (
    "portrait",
    "image",
    "signature_usual_mark",
    "signature_usual_mark_issuing_officer",
    "picture",
)
_SAMPLE_IMAGES = {"Port1": cfgserv.portrait1, "Port2": cfgserv.portrait2}
EHIC_CONFIGURATION = "eu.europa.ec.eudi.ehic_sd_jwt_vc"
SEAFARER_CONFIGURATION = "eu.europa.ec.eudi.seafarer_mdoc"
MDL_SCOPE = "org.iso.18013.5.1.mDL"
#: Largest list index accepted in a form key such as ``capacities[3][code]``.
MAX_FORM_INDEX = 99


class InvalidFormError(ValueError):
    """Raised when a submitted attribute form is malformed."""


def _form_index(part: str) -> int:
    """Converts a bracketed list index of a form key, within bounds.

    Args:
        part: Digits from the key.

    Returns:
        The index.

    Raises:
        InvalidFormError: Above :data:`MAX_FORM_INDEX` (a huge index would
            allocate a huge list).
    """
    idx = int(part)
    if idx > MAX_FORM_INDEX:
        raise InvalidFormError(f"Form list index {idx} exceeds {MAX_FORM_INDEX}")
    return idx


def _set_nested(target: Dict[str, Any], key: str, value: Any) -> None:
    """Stores ``value`` at the path encoded in a bracketed form key.

    E.g. ``capacities[0][codes][1][code]`` becomes
    ``target["capacities"][0]["codes"][1]["code"]``.

    Args:
        target: Root dict (mutated).
        key: Bracketed form key.
        value: Value to store.

    Raises:
        InvalidFormError: If a list index is too large.
    """
    parts = _KEY_PARTS.findall(key)
    current: Any = target
    for i, part in enumerate(parts[:-1]):
        if part.isdigit():
            idx = _form_index(part)
            while len(current) <= idx:
                current.append({})
            current = current[idx]
        else:
            next_is_index = i + 1 < len(parts) and parts[i + 1].isdigit()
            current = current.setdefault(part, [] if next_is_index else {})

    final_key = parts[-1]
    if final_key.isdigit() and isinstance(current, list):
        idx = _form_index(final_key)
        while len(current) <= idx:
            current.append(None)
        current[idx] = value
    else:
        current[final_key] = value


def _merge_places_of_work(cleaned_data: Dict[str, Any]) -> None:
    """Merges the per-row ``places_of_work`` entries produced by the form parser.

    ``[{'no_fixed_place': [a]}, {'no_fixed_place': [b]}]`` becomes
    ``[{'no_fixed_place': [a, b]}]``.

    Args:
        cleaned_data: Parsed form data (mutated).
    """
    places = cleaned_data.get("places_of_work")
    if not isinstance(places, list):
        return
    aggregated: Dict[str, List[Any]] = {}
    for item in places:
        if isinstance(item, dict):
            for key, value_list in item.items():
                aggregated.setdefault(key, [])
                if isinstance(value_list, list):
                    aggregated[key].extend(value_list)
    if aggregated:
        cleaned_data["places_of_work"] = [aggregated]


def form_formatter(form_data: Dict[str, Any], issuing_country: str) -> Dict[str, Any]:
    """Normalizes a submitted attribute form into the session user data.

    Args:
        form_data: Flat form fields (``field[]`` already collected as lists,
            see :func:`app.utils.forms.parse_form`). Mutated.
        issuing_country: Country of the issuance session.

    Returns:
        The nested, normalized user data (with ``issuing_country``).
    """
    if "effective_from_date" in form_data:
        form_data["effective_from_date"] = to_rfc3339(form_data["effective_from_date"])

    cleaned_data: Dict[str, Any] = {}
    # Sorted so parent structures (capacities[0]) are created before children.
    for key in sorted(form_data):
        value = form_data[key]
        if not value or key in _SKIPPED_FORM_KEYS:
            continue
        if "option" in key and "on" in value:
            continue
        _set_nested(cleaned_data, key, value)

    _merge_places_of_work(cleaned_data)

    for key in ("nationality", "nationalities"):
        values = cleaned_data.get(key)
        if isinstance(values, list) and values and isinstance(values[0], dict):
            country_codes = [item.get("country_code") for item in values if "country_code" in item]
            cleaned_data["nationality"] = country_codes
            cleaned_data["nationalities"] = country_codes
            break

    if isinstance(cleaned_data.get("birth_place"), list):
        cleaned_data["birth_place"] = cleaned_data["birth_place"][0]
        cleaned_data["place_of_birth"] = cleaned_data["birth_place"]
    if isinstance(cleaned_data.get("place_of_birth"), list):
        cleaned_data["place_of_birth"] = cleaned_data["place_of_birth"][0]
        cleaned_data["birth_place"] = cleaned_data["place_of_birth"]

    if "birth_date" in cleaned_data:
        cleaned_data["birthdate"] = cleaned_data["birth_date"]

    for field in ("signature_usual_mark", "signature_usual_mark_issuing_officer"):
        if cleaned_data.get(field) == "Sig1":
            cleaned_data[field] = cfgserv.signature_usual_mark_issuing_officer

    match cleaned_data.get("age_over_18"):
        case "true":
            cleaned_data["age_over_18"] = True
        case "false":
            cleaned_data["age_over_18"] = False

    # Sample image choices; anything else is the uploaded base64url image.
    final_data = {
        item: _SAMPLE_IMAGES.get(value, value) if item in _IMAGE_FIELDS and isinstance(value, str) else value
        for item, value in cleaned_data.items()
    }
    final_data["issuing_country"] = issuing_country
    return final_data


def _to_display_base64(value: str) -> str:
    """Converts base64url image data to standard base64 for display.

    Args:
        value: Base64url data.

    Returns:
        Standard base64 data.
    """
    return base64.b64encode(base64.urlsafe_b64decode(value)).decode("utf-8")


def presentation_formatter(
    cleaned_data: Dict[str, Any],
    credentials_requested: Iterable[str],
    country: str,
    include_optional: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """Builds the per-credential data shown on the consent page.

    Args:
        cleaned_data: User data (see :func:`form_formatter`).
        credentials_requested: Credential configuration ids.
        country: Issuing country.
        include_optional: Whether optional attributes are shown too.

    Returns:
        ``{credential display name: {attribute: value}}``.
    """
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    presentation_data: Dict[str, Dict[str, Any]] = {}

    for credential_requested in credentials_requested:
        credential_config = credentials_supported[credential_requested]
        name = credential_config["credential_metadata"]["display"][0]["name"]

        shown_attributes = set(getAttributesForm([credential_requested]))
        if include_optional:
            shown_attributes |= set(getAttributesForm2([credential_requested]))
        data = {k: v for k, v in cleaned_data.items() if k in shown_attributes}

        doctype_config = credential_config["issuer_config"]
        today = datetime.date.today()
        data["estimated_issuance_date"] = format_date(today)
        data["estimated_expiry_date"] = format_date(today + datetime.timedelta(days=doctype_config["validity"]))
        data["issuing_country"] = country

        if credential_requested == SEAFARER_CONFIGURATION:
            data["issuing_authority_logo"] = _to_display_base64(cfgserv.issuing_authority_logo)

        if credential_requested == EHIC_CONFIGURATION:
            data["issuing_authority"] = {
                "id": doctype_config["issuing_authority_id"],
                "name": doctype_config["issuing_authority"],
            }
        else:
            data["issuing_authority"] = doctype_config["issuing_authority"]

        if "credential_type" in doctype_config:
            data["credential_type"] = doctype_config["credential_type"]

        if "birth_date" in data and ("age_over_18" in data or credential_config["scope"] == MDL_SCOPE):
            data["age_over_18"] = calculate_age(data["birth_date"]) >= 18

        if isinstance(data.get("driving_privileges"), str):
            data["driving_privileges"] = json.loads(data["driving_privileges"])

        for field in _DISPLAY_DECODED_FIELDS:
            if field in data:
                data[field] = _to_display_base64(data[field])

        if "NumberCategories" in data:
            for i in range(1, int(data["NumberCategories"]) + 1):
                data.pop(f"IssueDate{i}")
                data.pop(f"ExpiryDate{i}")
            data.pop("NumberCategories")

        presentation_data[name] = data

    return presentation_data
