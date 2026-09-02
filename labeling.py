"""Transparent behavioral labeling rules used to create auditable pseudo-labels."""

from __future__ import annotations

from dataclasses import dataclass


THREAT_LEVELS = {
    "cryptomining": "critical",
    "botnet_activity": "critical",
    "malware_delivery": "critical",
    "post_exploitation": "critical",
    "reconnaissance": "high",
    "brute_force": "high",
    "credential_stuffing": "high",
    "password_spraying": "high",
    "dictionary_attack": "medium",
    "successful_login": "medium",
    "scanning": "low",
    "unknown": "low",
}


@dataclass(frozen=True)
class RuleDecision:
    label: str
    threat_level: str
    reason: str


def _decision(label: str, reason: str) -> RuleDecision:
    return RuleDecision(label, THREAT_LEVELS[label], reason)


def classify(features: dict[str, float]) -> RuleDecision:
    failures = int(features["login_failures"])
    successes = int(features["login_successes"])
    commands = int(features["command_count"])
    downloads = int(features["download_count"])
    unique_users = int(features["unique_usernames"])
    unique_passwords = int(features["unique_passwords"])
    attempts = failures + successes

    if features["miner_keyword_count"] > 0:
        return _decision("cryptomining", "Cryptomining indicators were found in submitted commands.")
    if features["botnet_keyword_count"] > 0:
        return _decision("botnet_activity", "Botnet or denial-of-service indicators were found in submitted commands.")
    if downloads > 0 or features["download_keyword_count"] > 0:
        return _decision("malware_delivery", "The session attempted a file transfer or used a download command.")
    if successes > 0 and commands > 0 and features["recon_command_ratio"] >= 0.60:
        return _decision("reconnaissance", "Most commands were host or filesystem discovery commands after login.")
    if successes > 0 and commands > 0:
        return _decision("post_exploitation", "Commands were executed after a successful login.")

    if failures >= 8 and unique_users >= 5 and unique_passwords <= max(2, round(attempts * 0.15)):
        return _decision("password_spraying", "Many usernames were tested with a small password set.")
    if failures >= 8 and features["unique_pair_ratio"] >= 0.75 and unique_users >= 4 and unique_passwords >= 4:
        return _decision("credential_stuffing", "Most attempts used distinct username/password pairs.")
    if failures >= 20 and features["attempts_per_minute"] >= 2:
        return _decision("brute_force", "A high-volume, machine-paced sequence of failed logins was observed.")
    if failures >= 6:
        return _decision("dictionary_attack", "Repeated failed logins used several candidate passwords.")
    if successes > 0:
        return _decision("successful_login", "Authentication succeeded but no follow-on command activity was recorded.")
    if failures > 0:
        return _decision("scanning", "Only a small number of login probes were observed.")
    return _decision("unknown", "The session did not contain enough authentication or command behavior to classify.")
