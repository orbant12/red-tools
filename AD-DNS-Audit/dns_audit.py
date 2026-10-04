#!/usr/bin/env python3
"""
adidns_audit.py - ADIDNS permission auditor

Binds to a domain controller over LDAP with supplied credentials, enumerates
every AD-integrated DNS zone across all partitions, parses each zone's
security descriptor and dynamic-update setting, and reports which principals
can add / modify-takeover / delete DNS records -- and whether the account you
authenticated with can.

Intended for authorized penetration tests and defensive auditing of domains
you own or have written permission to assess.

Dependencies:
    pip install ldap3 impacket

Examples:
    python3 adidns_audit.py -d logging.htb -u svcuser -p 'Passw0rd' --dc-ip 10.10.11.x
    python3 adidns_audit.py -d corp.local -u jdoe --hashes :<nthash> --dc-ip dc01 --expand
    python3 adidns_audit.py -d corp.local -u jdoe -p pw --dc-ip dc01 -o report.md
"""

import argparse
import json
import sys
import struct
import hashlib
from datetime import datetime, timezone

# --- MD4 shim: OpenSSL 3 removed MD4 from the default provider, but ldap3's
# NTLM auth needs it. Route hashlib.new('md4') through pycryptodome if missing.
try:
    hashlib.new("md4")
except (ValueError, TypeError):
    try:
        from Cryptodome.Hash import MD4 as _MD4
    except ImportError:
        from Crypto.Hash import MD4 as _MD4
    _orig_new = hashlib.new
    def _patched_new(name, data=b"", **kw):
        if str(name).lower() == "md4":
            h = _MD4.new()
            if data:
                h.update(data)
            return h
        return _orig_new(name, data, **kw)
    hashlib.new = _patched_new

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, BASE
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    sys.exit("[!] Missing dependency: pip install ldap3")

try:
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string
except ImportError:
    sys.exit("[!] Missing dependency: pip install impacket")


# --- AD access-mask bits (ADS_RIGHTS) -----------------------------------------
CREATE_CHILD   = 0x00000001   # add child objects (= add DNS records on a zone)
DELETE_CHILD   = 0x00000002   # delete child objects (= delete records)
WRITE_PROP     = 0x00000020
DELETE         = 0x00010000
WRITE_DACL     = 0x00040000   # rewrite the DACL -> takeover
WRITE_OWNER    = 0x00080000   # take ownership -> takeover
GENERIC_ALL    = 0x10000000   # full control
GENERIC_WRITE  = 0x40000000

# dnsNode objectClass GUID -- an object-ACE scoped to this means "DNS records"
DNSNODE_GUID = "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9".lower()

# dNSProperty id 0x02 = DSPROPERTY_ZONE_ALLOW_UPDATE  (NOTE: id 0x01 is ZONE_TYPE)
PROP_ALLOW_UPDATE = 0x02
ALLOW_UPDATE_MAP = {
    0: "None (no dynamic updates)",
    1: "Nonsecure AND secure  <-- UNAUTHENTICATED users can add records",
    2: "Secure only (default for AD-integrated)",
}

# Well-known SIDs we care about (broad principals that mean "lots of people")
WELLKNOWN = {
    "S-1-1-0":     ("Everyone", True),
    "S-1-5-7":     ("Anonymous", True),
    "S-1-5-11":    ("Authenticated Users", True),
    "S-1-5-2":     ("Network", True),
    "S-1-5-9":     ("Enterprise Domain Controllers", False),
    "S-1-5-32-544":("BUILTIN\\Administrators", False),
    "S-1-5-18":    ("LOCAL SYSTEM", False),
    "S-1-3-0":     ("Creator Owner", False),
    "S-1-5-32-554":("BUILTIN\\Pre-Windows 2000 Compatible Access", True),
}
# SIDs whose create/write rights are expected (not a finding on their own)
EXPECTED_ADMIN_SIDS = {"S-1-5-32-544", "S-1-5-18", "S-1-5-9"}
EXPECTED_ADMIN_RIDS = {512, 519, 518, 516}  # Domain/Enterprise/Schema Admins, DCs


def parse_dnsproperty(values):
    """Return the allow-update code (int) from a dNSProperty multivalue, or None."""
    for raw in values or []:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 20:
            continue
        data_len = struct.unpack("<I", raw[0:4])[0]
        prop_id  = struct.unpack("<I", raw[16:20])[0]
        data     = raw[20:20 + data_len]
        if prop_id == PROP_ALLOW_UPDATE and len(data) >= 4:
            return struct.unpack("<I", data[0:4])[0]
    return None


def sid_to_filter(sid_bytes):
    return "".join("\\%02x" % b for b in sid_bytes)


def mask_to_rights(mask):
    names = []
    for bit, name in [
        (CREATE_CHILD, "CREATE_CHILD"), (DELETE_CHILD, "DELETE_CHILD"),
        (WRITE_PROP, "WRITE_PROP"), (DELETE, "DELETE"),
        (WRITE_DACL, "WRITE_DACL"), (WRITE_OWNER, "WRITE_OWNER"),
        (GENERIC_WRITE, "GENERIC_WRITE"), (GENERIC_ALL, "GENERIC_ALL"),
    ]:
        if mask & bit:
            names.append(name)
    return names


def classify(mask):
    """Return the set of capability tags this mask grants over DNS records."""
    caps = set()
    if mask & (CREATE_CHILD | GENERIC_ALL):
        caps.add("ADD")
    if mask & (DELETE_CHILD | GENERIC_ALL):
        caps.add("DELETE")
    if mask & (WRITE_DACL | WRITE_OWNER | GENERIC_ALL):
        caps.add("TAKEOVER")
    return caps


def ace_object_applies_to_records(ace):
    """True if the ACE is unscoped (all child objects) or scoped to dnsNode."""
    inner = ace["Ace"]
    # ACCESS_ALLOWED_ACE (non-object) applies to all child objects
    if ace["TypeName"] == "ACCESS_ALLOWED_ACE":
        return True
    if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
        flags = inner["Flags"]
        if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
            try:
                guid = bin_to_string(inner["ObjectType"]).lower()
            except Exception:
                return False
            return guid == DNSNODE_GUID
        return True  # object ACE with no ObjectType = all child objects
    return False


SEVERITY_ORDER = {"OK": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def assess(allow_code, grants):
    """Return (severity, reason) for a zone."""
    broad_add = broad_take = deleg_add = deleg_take = False
    for g in grants:
        caps, broad, exp = set(g["capabilities"]), g["broad"], g["expected_admin"]
        if broad and "TAKEOVER" in caps: broad_take = True
        if broad and "ADD" in caps:      broad_add = True
        if not broad and not exp and "TAKEOVER" in caps: deleg_take = True
        if not broad and not exp and "ADD" in caps:      deleg_add = True

    if allow_code == 1:
        return "CRITICAL", "Nonsecure dynamic updates: unauthenticated users can add records"
    if broad_take:
        return "CRITICAL", "A broad principal (Everyone/Auth Users) can rewrite the zone DACL"
    if deleg_take:
        return "HIGH", "Non-admin principal can take over the zone (WriteDacl/WriteOwner/GenericAll)"
    if deleg_add:
        return "HIGH", "Non-admin principal can add records (delegated CreateChild)"
    if broad_add:
        return "MEDIUM", "Any authenticated user can add records (ADIDNS spoofing exposure; default)"
    return "OK", "Only expected admins/DCs can write"


class Resolver:
    def __init__(self, conn, base):
        self.conn = conn
        self.base = base
        self.cache = {}

    def resolve(self, sid_bytes):
        sid = ldaptypes.LDAP_SID(data=sid_bytes).formatCanonical()
        if sid in self.cache:
            return self.cache[sid], sid
        if sid in WELLKNOWN:
            label = WELLKNOWN[sid][0]
            self.cache[sid] = label
            return label, sid
        label = sid
        try:
            if self.conn.search(self.base, f"(objectSid={sid_to_filter(sid_bytes)})",
                                 search_scope=SUBTREE,
                                 attributes=["sAMAccountName", "objectClass"]):
                for e in self.conn.entries:
                    label = str(e.sAMAccountName) or sid
                    break
        except Exception:
            pass
        self.cache[sid] = label
        return label, sid


def rid_of(sid):
    try:
        return int(sid.rsplit("-", 1)[1])
    except Exception:
        return None


def get_self_sids(conn, base, username):
    """SIDs the bound user effectively carries (own SID + nested groups + broad)."""
    sids = {"S-1-5-11", "S-1-1-0", "S-1-5-2"}  # authenticated users / everyone / network
    try:
        if conn.search(base, f"(sAMAccountName={username})", search_scope=SUBTREE,
                       attributes=["distinguishedName"]):
            dn = str(conn.entries[0].distinguishedName)
            if conn.search(dn, "(objectClass=*)", search_scope=BASE,
                           attributes=["tokenGroups", "objectSid"]):
                e = conn.entries[0]
                if "objectSid" in e:
                    sids.add(str(e.objectSid))
                for raw in (e.tokenGroups.raw_values if "tokenGroups" in e else []):
                    sids.add(ldaptypes.LDAP_SID(data=raw).formatCanonical())
    except Exception as ex:
        print(f"[!] Could not compute effective groups for {username}: {ex}", file=sys.stderr)
    return sids


def expand_group(conn, base, sid, sid_bytes):
    """Return nested user members of a group SID via LDAP_MATCHING_RULE_IN_CHAIN."""
    members = []
    try:
        if conn.search(base, f"(objectSid={sid_to_filter(sid_bytes)})",
                       search_scope=SUBTREE, attributes=["distinguishedName"]):
            gdn = str(conn.entries[0].distinguishedName)
            flt = f"(&(objectCategory=person)(objectClass=user)" \
                  f"(memberOf:1.2.840.113556.1.4.1941:={gdn}))"
            if conn.search(base, flt, search_scope=SUBTREE, attributes=["sAMAccountName"]):
                members = sorted({str(e.sAMAccountName) for e in conn.entries})
    except Exception:
        pass
    return members


def audit_zone(entry, resolver, self_sids, expand, conn, base):
    name = str(entry.name) if "name" in entry else str(entry.dc) if "dc" in entry else "?"
    raw_sd = entry.nTSecurityDescriptor.raw_values[0]
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)

    allow_code = parse_dnsproperty(entry.nTSecurityDescriptor.raw_values and
                                   (entry.dNSProperty.raw_values if "dNSProperty" in entry else []))

    findings = []       # list of dicts per granting principal
    self_can = set()
    for ace in sd["Dacl"].aces:
        inner = ace["Ace"]
        if ace["TypeName"] not in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
            # we flag only Allow ACEs; deny handled separately below
            continue
        mask = inner["Mask"]["Mask"]
        caps = classify(mask)
        if not caps or not ace_object_applies_to_records(ace):
            continue
        sid_bytes = inner["Sid"].getData()
        label, sid = resolver.resolve(sid_bytes)
        broad = WELLKNOWN.get(sid, (None, False))[1]
        expected = sid in EXPECTED_ADMIN_SIDS or rid_of(sid) in EXPECTED_ADMIN_RIDS \
                   or "admins" in label.lower()
        rec = {
            "principal": label,
            "sid": sid,
            "rights": mask_to_rights(mask),
            "capabilities": sorted(caps),
            "broad": broad,
            "expected_admin": expected,
            "members": [],
        }
        if expand and not broad and not expected:
            rec["members"] = expand_group(conn, base, sid, sid_bytes)
        findings.append(rec)
        if sid in self_sids:
            self_can |= caps

    # deny ACEs worth noting
    denies = []
    for ace in sd["Dacl"].aces:
        if ace["TypeName"] in ("ACCESS_DENIED_ACE", "ACCESS_DENIED_OBJECT_ACE"):
            sid_bytes = ace["Ace"]["Sid"].getData()
            label, sid = resolver.resolve(sid_bytes)
            denies.append({"principal": label, "sid": sid,
                           "rights": mask_to_rights(ace["Ace"]["Mask"]["Mask"])})

    owner_sid = ldaptypes.LDAP_SID(data=sd["OwnerSid"].getData()).formatCanonical()
    owner_label, _ = resolver.resolve(sd["OwnerSid"].getData())

    severity, reason = assess(allow_code, findings)

    return {
        "severity": severity,
        "reason": reason,
        "zone": name,
        "dn": str(entry.distinguishedName),
        "owner": owner_label,
        "owner_sid": owner_sid,
        "allow_update_code": allow_code,
        "allow_update": ALLOW_UPDATE_MAP.get(allow_code, f"unknown ({allow_code})"),
        "grants": findings,
        "denies": denies,
        "self_capabilities": sorted(self_can),
    }


def enumerate_zones(conn, default_nc, root_nc):
    bases = [
        f"CN=MicrosoftDNS,DC=DomainDnsZones,{default_nc}",
        f"CN=MicrosoftDNS,DC=ForestDnsZones,{root_nc}",
        f"CN=MicrosoftDNS,CN=System,{default_nc}",
    ]
    attrs = ["name", "dc", "distinguishedName", "nTSecurityDescriptor", "dNSProperty"]
    ctrl = security_descriptor_control(sdflags=0x05)  # OWNER + DACL
    seen, zones = set(), []
    for b in bases:
        try:
            ok = conn.search(b, "(objectClass=dnsZone)", search_scope=SUBTREE,
                             attributes=attrs, controls=ctrl)
        except Exception as ex:
            print(f"[.] partition not searched: {b} ({ex})", file=sys.stderr)
            continue
        if not ok:
            continue
        for e in conn.entries:
            dn = str(e.distinguishedName)
            if dn not in seen and "nTSecurityDescriptor" in e:
                seen.add(dn)
                zones.append(e)
    return zones


def render_report(domain, dc, results, bound_user):
    L = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L.append(f"# ADIDNS permission audit — {domain}")
    L.append("")
    L.append(f"- DC queried: `{dc}`")
    L.append(f"- Bound as: `{bound_user}`")
    L.append(f"- Generated: {now}")
    L.append(f"- Zones found: {len(results)}")
    worst = max(results, key=lambda r: SEVERITY_ORDER[r["severity"]])["severity"]
    L.append(f"- **Overall: {worst}**")
    L.append("")
    for r in sorted(results, key=lambda r: -SEVERITY_ORDER[r["severity"]]):
        L.append(f"## [{r['severity']}] `{r['zone']}` — {r['reason']}")
        L.append("")
        L.append(f"- DN: `{r['dn']}`")
        L.append(f"- Owner: {r['owner']}")
        L.append(f"- Dynamic updates: {r['allow_update']}")
        sc = ", ".join(r["self_capabilities"]) or "none"
        L.append(f"- **Bound user ({bound_user}) can: {sc}**")
        L.append("")
        if r["grants"]:
            L.append("| Principal | Capabilities | Rights | Scope note |")
            L.append("|---|---|---|---|")
            for g in sorted(r["grants"], key=lambda x: (x["expected_admin"], x["principal"])):
                note = []
                if g["broad"]: note.append("BROAD / many users")
                if g["expected_admin"]: note.append("expected admin")
                if g["members"]: note.append(f"{len(g['members'])} nested member(s)")
                L.append(f"| {g['principal']} | {', '.join(g['capabilities'])} "
                         f"| {', '.join(g['rights'])} | {'; '.join(note) or '-'} |")
            L.append("")
            # interesting (non-admin) principals that can add/takeover
            interesting = [g for g in r["grants"]
                           if not g["expected_admin"] and ("ADD" in g["capabilities"]
                                                           or "TAKEOVER" in g["capabilities"])]
            for g in interesting:
                if g["members"]:
                    L.append(f"  - `{g['principal']}` members: "
                             + ", ".join(f"`{m}`" for m in g["members"][:50])
                             + (" ..." if len(g["members"]) > 50 else ""))
            if interesting:
                L.append("")
        if r["denies"]:
            L.append("Deny ACEs present:")
            for d in r["denies"]:
                L.append(f"  - {d['principal']}: {', '.join(d['rights'])}")
            L.append("")
    L.append("---")
    L.append("_Note: ADD = can create new records (CreateChild/GenericAll). "
             "TAKEOVER = can rewrite the zone DACL/owner (WriteDacl/WriteOwner/GenericAll). "
             "Modifying an EXISTING record depends on that record's own owner/DACL, "
             "which is per-node and not shown here (creator owns the node)._")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="ADIDNS permission auditor")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password")
    ap.add_argument("--hashes", help="LMHASH:NTHASH or :NTHASH")
    ap.add_argument("--dc-ip", "--host", dest="host", required=True,
                    help="DC hostname or IP")
    ap.add_argument("--ldaps", action="store_true", help="use LDAPS/636")
    ap.add_argument("--expand", action="store_true",
                    help="resolve nested members of non-admin groups that can add/takeover")
    ap.add_argument("-o", "--output", help="write markdown report to this path")
    ap.add_argument("--json", help="also write raw findings to this JSON path")
    args = ap.parse_args()

    if not args.password and not args.hashes:
        ap.error("provide -p/--password or --hashes")
    secret = args.password if args.password else args.hashes

    port = 636 if args.ldaps else 389
    server = Server(args.host, port=port, use_ssl=args.ldaps, get_info=ALL)
    try:
        conn = Connection(server, user=f"{args.domain}\\{args.username}",
                          password=secret, authentication=NTLM, auto_bind=True)
    except Exception as ex:
        sys.exit(f"[!] LDAP bind failed: {ex}")
    print(f"[+] Bound to {args.host} as {args.domain}\\{args.username}")

    info = server.info
    default_nc = info.other.get("defaultNamingContext", [None])[0]
    root_nc = info.other.get("rootDomainNamingContext", [default_nc])[0]
    if not default_nc:
        sys.exit("[!] Could not read defaultNamingContext from RootDSE")

    self_sids = get_self_sids(conn, default_nc, args.username)
    resolver = Resolver(conn, default_nc)

    zones = enumerate_zones(conn, default_nc, root_nc)
    if not zones:
        sys.exit("[!] No DNS zones readable (wrong partition, or no read access).")
    print(f"[+] Enumerated {len(zones)} zone(s)")

    results = [audit_zone(z, resolver, self_sids, args.expand, conn, default_nc)
               for z in zones]

    # console summary
    worst = max(results, key=lambda r: SEVERITY_ORDER[r["severity"]])["severity"]
    print(f"\n[=] Overall: {worst}\n")
    for r in sorted(results, key=lambda r: -SEVERITY_ORDER[r["severity"]]):
        print(f"  [{r['severity']:<8}] {r['zone']:<35} {r['reason']}")

    report = render_report(args.domain, args.host, results, args.username)
    out = args.output or f"adidns_report_{args.domain}.md"
    with open(out, "w") as f:
        f.write(report)
    print(f"[+] Report written: {out}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] JSON written: {args.json}")


if __name__ == "__main__":
    main()
