"""Offline tests: subscription parsing and config loading. Run: python3 -m unittest discover -s tests"""
import base64
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))
os.environ.setdefault("CONFIG", "/nonexistent/config.toml")

import config  # noqa: E402
import manager as M  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
VLESS = (f"vless://{UUID}@node1.example.com:443?type=tcp&security=reality&pbk=PUBKEY&sid=ab12"
         "&sni=www.example.org&fp=chrome&flow=xtls-rprx-vision#%F0%9F%87%A9%F0%9F%87%AA%20Germany")
TROJAN = "trojan://secret@node2.example.com:8443?type=ws&path=%2Fws&host=cdn.example.com#Trojan"
SS = "ss://" + base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:pass").decode().rstrip("=") + "@node3.example.com:8388#SS"
HY2 = "hysteria2://auth@node4.example.com:443?sni=h.example.com&insecure=1#Hy2"
VMESS = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "VMess", "add": "node5.example.com", "port": "443", "id": UUID, "aid": "0",
    "net": "ws", "path": "/v", "host": "cdn.example.com", "tls": "tls", "sni": "cdn.example.com"}).encode()).decode()


class ParseTest(unittest.TestCase):
    def test_vless_reality(self):
        out, name = M.parse_link(VLESS)
        self.assertEqual(name, "🇩🇪 Germany")
        self.assertEqual(out["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        r = out["streamSettings"]["realitySettings"]
        self.assertEqual((r["publicKey"], r["shortId"], r["serverName"]), ("PUBKEY", "ab12", "www.example.org"))
        self.assertEqual(M.flag_country(name), "DE")

    def test_other_schemes(self):
        self.assertEqual(M.parse_link(TROJAN)[0]["streamSettings"]["wsSettings"]["path"], "/ws")
        ss = M.parse_link(SS)[0]["settings"]["servers"][0]
        self.assertEqual((ss["method"], ss["password"], ss["port"]), ("chacha20-ietf-poly1305", "pass", 8388))
        hy = M.parse_link(HY2)[0]
        self.assertTrue(hy["streamSettings"]["tlsSettings"]["allowInsecure"])
        vm = M.parse_link(VMESS)[0]
        self.assertEqual(vm["streamSettings"]["security"], "tls")

    def test_unsupported(self):
        with self.assertRaises(M.Unsupported):
            M.parse_link("ss://YWVzLTEyOC1nY206cGFzcw@h.example.com:1?plugin=obfs#x")
        with self.assertRaises(M.Unsupported):
            M.parse_link("tuic://x@h.example.com:1#x")

    def test_base64_subscription(self):
        body = base64.b64encode("\n".join([VLESS, TROJAN, SS, HY2, VMESS, "tuic://x@h:1#t"]).encode())
        nodes, skipped = M.parse_subscription("s", body)
        self.assertEqual(len(nodes), 5)
        self.assertEqual(skipped["scheme tuic"], 1)

    def test_name_id_survives_rotating_params(self):
        """Providers rotate SNI/shortId per fetch: a unique name must keep the id stable."""
        a = M.parse_subscription("s", VLESS.encode())[0][0]
        b = M.parse_subscription("s", VLESS.replace("sid=ab12", "sid=cd34").encode())[0][0]
        self.assertEqual(a.id, b.id)
        self.assertTrue(a.id.startswith("n"))

    def test_duplicate_names_hash_params(self):
        body = "\n".join([TROJAN, TROJAN.replace("node2", "node9")]).encode()
        nodes = M.parse_subscription("s", body)[0]
        self.assertEqual(len(nodes), 2)
        self.assertFalse(any(n.id.startswith("n") for n in nodes))

    def test_json_subscription_with_chain(self):
        cfg = [{"remarks": "Chain", "outbounds": [
            {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "a.example.com", "port": 443, "users": [{"id": UUID}]}]},
             "streamSettings": {"sockopt": {"dialerProxy": "hop"}}},
            {"tag": "hop", "protocol": "shadowsocks", "settings": {"servers": [{"address": "b.example.com", "port": 1, "method": "m", "password": "p"}]}},
            {"tag": "direct", "protocol": "freedom"}]}]
        nodes = M.parse_subscription("s", json.dumps(cfg).encode())[0]
        names = sorted(n.name for n in nodes)
        self.assertEqual(names, ["Chain · hop", "Chain · proxy"])
        chained = next(n for n in nodes if n.name.endswith("proxy"))
        self.assertEqual(len(chained.outbounds), 2)
        out = M.retag(chained, "a-x", "z-x-")
        self.assertEqual(out[0]["streamSettings"]["sockopt"]["dialerProxy"], "z-x-1")

    def test_placeholder_prod_config(self):
        cfg = M.Manager.prod_config(None, None, [])
        self.assertEqual(cfg["outbounds"][0]["protocol"], "blackhole")
        self.assertEqual(cfg["routing"]["balancers"][0]["selector"], ["a-none"])


class ConfigTest(unittest.TestCase):
    def load(self, text, **env):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        os.environ.update(env)
        try:
            return config.load(f.name, required=True)
        finally:
            os.remove(f.name)

    def test_env_and_priority(self):
        cfg = self.load('[[subscription]]\nname="b"\nurl="${T_URL}"\npriority=2\n'
                        '[[subscription]]\nname="a"\nurl="https://x.example.com/a"\npriority=1\nflags=["free"]\n'
                        '[selection]\nblocked_countries=["RU"]\n', T_URL="https://x.example.com/b")
        self.assertEqual([s["name"] for s in cfg["subscription"]], ["a", "b"])
        self.assertEqual(cfg["subscription"][1]["url"], "https://x.example.com/b")
        self.assertEqual(cfg["selection"]["blocked_countries"], ["RU"])
        self.assertEqual(cfg["selection"]["max_latency_ms"], 800)

    def test_errors(self):
        for bad in ('[[subscription]]\nname="a b"\nurl="https://x"\n',
                    '[[subscription]]\nname="a"\nurl="${MISSING_VAR_X}"\n',
                    '[[subscription]]\nname="a"\nurl="https://x"\nflags=["nope"]\n',
                    '[[subscription]]\nname="a"\nurl="https://x"\n[[subscription]]\nname="a"\nurl="https://y"\n',
                    '[[subscription]]\nname="a"\nurl="https://x"\n[notify]\nmin_severity="loud"\n',
                    ''):
            with self.subTest(bad=bad), self.assertRaises(config.ConfigError):
                self.load(bad)

    def test_example_config_is_valid(self):
        path = pathlib.Path(__file__).resolve().parent.parent / "examples" / "config.toml"
        os.environ["SUB_MAIN_URL"] = "https://x.example.com/main"
        cfg = config.load(str(path), required=True)
        self.assertEqual(len(cfg["subscription"]), 2)


if __name__ == "__main__":
    unittest.main()
