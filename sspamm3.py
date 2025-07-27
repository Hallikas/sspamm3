#!/usr/bin/env python3
"""
Sspamm3 - Semi's Spam Milter

A Python 3-based milter for filtering spam emails using regex-based rules.
Supports domain-specific filtering and JSON-based email logging.
Designed for integration with Postfix or other mail servers via the Milter protocol.

Author: Sami-Pekka Hallikas
Email: sspamm@hallikas.com
License: MIT
Version: 0.1.0
Last Updated: July 27, 2025
"""

import argparse
import configparser
import json
import re
from typing import Dict, List, Optional, Tuple
from Milter import Milter, CONTINUE, REJECT, ACCEPT

# Global configuration
conf: configparser.ConfigParser = None
compiled_rules: Dict[str, List[Tuple[re.Pattern, str]]] = {}

def debug(msg: str, level: int, id: Optional[int] = None) -> None:
    """Log debug messages based on configured debug level."""
    try:
        if level <= int(conf.get("main", "debug", fallback="0")):
            print(f"DEBUG[{id}]: {msg}")
    except:
        print(f"E DEBUG[{id}]: {msg}")

def load_config(config_file: str) -> Tuple[configparser.ConfigParser, Dict]:
    """Load and compile configuration from sspamm3.conf."""
    debug("FUNC load_config", 1)
    global conf, compiled_rules
    config = configparser.ConfigParser()
    config.read(config_file)
    compiled_rules = {}
    for section in config.sections():
        compiled_rules[section] = []
        if section in ["ipfromto", "headers", "wordscan"]:
            for _, pattern in config[section].items():
                match = re.match(r"\(\?#(\w+)\)", pattern)
                action = match.group(1) if match else "delete"
                try:
                    compiled_rules[section].append((re.compile(pattern), action))
                except re.error as e:
                    debug(f"Invalid regex in [{section}]: {pattern} ({e})", 1)
    conf = config
    debug("Configuration loaded", 1)
    return config, compiled_rules

def load_json(fname: str, id: Optional[int] = None) -> Dict:
    """Load email metadata from a JSON file."""
    debug("FUNC load_json", 1, id=id)
    try:
        with open(fname, "r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        debug(f"load_json failed: {e}", 1, id=id)
        raise

def load_vars(fname: str, id: Optional[int] = None) -> Dict:
    """Load email metadata from an old .var file."""
    debug("FUNC load_vars", 1, id=id)
    try:
        with open(fname, "r", encoding="utf-8") as f:
            # Placeholder for .var parsing logic (assumes key-value or similar format)
            # TODO: Implement actual .var parsing based on old format
            data = {}
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    data[key.strip()] = value.strip()
            return data
    except IOError as e:
        debug(f"load_vars failed: {e}", 1, id=id)
        raise

def save_json(mail: Dict, fname: str, id: Optional[int] = None) -> None:
    """Save email metadata to a JSON file."""
    debug("FUNC save_json", 1, id=id)
    try:
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(mail, f, indent=2, ensure_ascii=False)
        debug(f"Saved JSON to {fname}", 1, id=id)
    except (IOError, TypeError, ValueError) as e:
        debug(f"save_json failed: {e}", 1, id=id)

def test_ipfromto(mail: Dict, recipient_email: str, id: Optional[int] = None) -> Tuple[Optional[str], Optional[str]]:
    """Test ipfromto patterns."""
    debug("FUNC test_ipfromto", 1, id=id)
    ipfromto = f"{mail['received']['1']['dns']}:{mail['from'][0]}"
    mail["ipfromto"] = {recipient_email: [ipfromto]}
    for pattern, action in compiled_rules.get("ipfromto", []):
        if pattern.search(ipfromto):
            mail["result"]["ipfromto"] = [action, ipfromto]
            mail["action"].append(action)
            if action == "delete":
                return action, "550 5.7.1 Message rejected as spam"
            break
    return None, None

def test_headers(mail: Dict, id: Optional[int] = None) -> Tuple[Optional[str], Optional[str]]:
    """Test headers patterns."""
    debug("FUNC test_headers", 1, id=id)
    for name, value in mail.get("header", {}).items():
        for pattern, action in compiled_rules.get("headers", []):
            if pattern.search(f"{name}:{value}"):
                mail["result"]["headers"] = [action, f"{name}:{value}"]
                mail["action"].append(action)
                if action == "delete":
                    return action, "550 5.7.1 Message rejected as spam"
                break
    return None, None

def test_wordscan(mail: Dict, id: Optional[int] = None) -> Tuple[Optional[str], Optional[str]]:
    """Test wordscan patterns on subject."""
    debug("FUNC test_wordscan", 1, id=id)
    subject = mail.get("subject", "")
    for pattern, action in compiled_rules.get("wordscan", []):
        if pattern.search(subject):
            mail["result"]["wordscan"] = [action, subject]
            mail["action"].append(action)
            if action == "delete":
                return action, "550 5.7.1 Message rejected as spam"
            break
    return None, None

def filter_email(mail: Dict, domain: str, sender_email: str, recipient_email: str, id: Optional[int] = None) -> Tuple[List[str], Optional[str]]:
    """Apply filtering rules to email."""
    debug("FUNC filter_email", 1, id=id)
    tests = conf.get("domains", domain, fallback=conf.get("domains", "default", fallback="")).split(", ")
    actions = []
    smtp_reply = None

    for test in tests:
        if test == "ipfromto":
            action, reply = test_ipfromto(mail, recipient_email, id)
            if action:
                actions.append(action)
                if reply:
                    smtp_reply = reply
                    break
        elif test == "headers":
            action, reply = test_headers(mail, id)
            if action:
                actions.append(action)
                if reply:
                    smtp_reply = reply
                    break
        elif test == "wordscan":
            action, reply = test_wordscan(mail, id)
            if action:
                actions.append(action)
                if reply:
                    smtp_reply = reply
                    break

    return actions, smtp_reply

class Sspamm3Milter(Milter):
    """Milter class for processing emails with regex-based filtering."""
    def __init__(self):
        debug("CLASS Sspamm3Milter __init__", 1)
        super().__init__()
        self.id: Optional[int] = None
        self.mail: Dict = {}

    def connect(self, hostname: str, family: str, ip: str, port: int, addr: str) -> int:
        """Handle SMTP connect event."""
        debug("Cfunc SM connect", 1)
        self.id = self.get_id()
        self.mail = {
            "id": self.id,
            "received": {"1": {"ip": ip, "helo": hostname, "dns": addr}},
            "action": [],
            "result": {}
        }
        return CONTINUE

    def envfrom(self, sender: str) -> int:
        """Handle SMTP MAIL FROM event."""
        debug("Cfunc SM envfrom", 1)
        self.mail["from"] = [sender]
        return CONTINUE

    def envrcpt(self, recipient: str) -> int:
        """Handle SMTP RCPT TO event."""
        debug("Cfunc SM envrcpt", 1)
        self.mail.setdefault("to", []).append(recipient)
        return CONTINUE

    def header(self, name: str, value: str) -> int:
        """Handle SMTP header event."""
        debug("Cfunc SM header", 1)
        self.mail.setdefault("header", {})[name] = value
        if name.lower() == "subject":
            self.mail["subject"] = value
        return CONTINUE

    def eom(self) -> int:
        """Handle end of message, apply filtering rules."""
        debug("Cfunc SM eom", 1)
        domain = self.mail["to"][0].split("@")[1] if self.mail.get("to") else "default"
        sender_email = self.mail["from"][0] if self.mail.get("from") else ""
        recipient_email = self.mail["to"][0] if self.mail.get("to") else ""

        actions, smtp_reply = filter_email(self.mail, domain, sender_email, recipient_email, self.id)
        if smtp_reply:
            self.setreply(smtp_reply.split()[0], smtp_reply)
            return REJECT

        save_json(self.mail, f"{conf.get('main', 'savedir')}/{self.id:08d}", self.id)
        return ACCEPT

class Test:
    """Class for offline testing of saved JSON email files."""
    def __init__(self, fname: str):
        debug("CLASS Test __init__", 1)
        try:
            if fname.endswith(".var"):
                self.mail = load_vars(fname)
            else:
                self.mail = load_json(fname)
            self.process()
        except (IOError, json.JSONDecodeError) as e:
            debug(f"load_json failed: {e}", 1)

    def process(self) -> None:
        """Process email with configured tests."""
        debug("Cfunc Test process", 1)
        domain = self.mail["to"][0].split("@")[1] if self.mail.get("to") else "default"
        sender_email = self.mail["from"][0] if self.mail.get("from") else ""
        recipient_email = self.mail["to"][0] if self.mail.get("to") else ""
        filter_email(self.mail, domain, sender_email, recipient_email, self.mail["id"])

def main():
    """Main entry point for the milter."""
    debug("FUNC main", 1)
    parser = argparse.ArgumentParser(description="Sspamm3 - Semi's Spam Milter")
    parser.add_argument("--test", help="Test a JSON file offline")
    parser.add_argument("--config", default="sspamm3.conf", help="Configuration file")
    args = parser.parse_args()
    load_config(args.config)
    if args.test:
        Test(args.test)
    else:
        Milter.run(Sspamm3Milter)

if __name__ == "__main__":
    main()
