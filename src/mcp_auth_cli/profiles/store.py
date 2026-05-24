"""Persistent profile storage."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from mcp_auth_cli.models import Profile


def default_cli_home() -> Path:
    override = os.environ.get("MCP_AUTH_CLI_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "mcp-auth"


class ProfileStore:
    """File-backed profile storage with active-profile tracking."""

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or default_cli_home()
        self.path = self.home / "profiles.json"

    def list_profiles(self) -> list[Profile]:
        data = self._load()
        return [Profile.from_dict(item) for item in data["profiles"]]

    def get_profile(self, profile_id: str) -> Profile | None:
        for profile in self.list_profiles():
            if profile.profile_id == profile_id:
                return profile
        return None

    def get_active_profile(self, resource_url: str) -> Profile | None:
        data = self._load()
        profile_id = data["active_profiles"].get(resource_url)
        if profile_id is None:
            return None
        return self.get_profile(profile_id)

    def save_profile(self, profile: Profile, *, make_active: bool = True) -> Profile:
        data = self._load()
        profiles = [Profile.from_dict(item) for item in data["profiles"]]
        for index, existing in enumerate(profiles):
            if existing.profile_id == profile.profile_id:
                profiles[index] = profile
                break
        else:
            if not profile.profile_id:
                profile.profile_id = uuid4().hex
            profiles.append(profile)
        data["profiles"] = [item.to_dict() for item in profiles]
        if make_active:
            data["active_profiles"][profile.resource_url] = profile.profile_id
        self._save(data)
        return profile

    def create_profile(self, profile: Profile, *, make_active: bool = True) -> Profile:
        if not profile.profile_id:
            profile.profile_id = uuid4().hex
        return self.save_profile(profile, make_active=make_active)

    def set_active_profile(self, resource_url: str, profile_id: str) -> None:
        data = self._load()
        data["active_profiles"][resource_url] = profile_id
        self._save(data)

    def delete_profile(self, profile_id: str) -> None:
        data = self._load()
        profiles = [item for item in data["profiles"] if item["profile_id"] != profile_id]
        data["profiles"] = profiles
        active_profiles = {
            resource: active_id
            for resource, active_id in data["active_profiles"].items()
            if active_id != profile_id
        }
        data["active_profiles"] = active_profiles
        self._save(data)

    def upsert_active_profile(self, profile: Profile) -> Profile:
        profile.touch()
        return self.save_profile(profile, make_active=True)

    def _load(self) -> dict[str, object]:
        if not self.path.exists():
            return {"profiles": [], "active_profiles": {}}
        return json.loads(self.path.read_text())

    def _save(self, data: dict[str, object]) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.home, 0o700)
        except OSError:
            pass
        temp_path = self.path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.replace(temp_path, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
