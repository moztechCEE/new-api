"""Offline behavioral checks for the isolated deployment bootstrap scripts."""

import contextlib
import io
import json
import os
import pathlib
import runpy
import stat
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock


SCRIPT_DIRECTORY = pathlib.Path(__file__).resolve().parent
TEST_PASSWORD = "unit-test-only-password-" + "p" * 43
TEST_TOKEN = "unit-test-only-management-token"


def management_opener(responses):
    opener = mock.Mock()
    opener.open.side_effect = [
        response
        if isinstance(response, BaseException)
        else io.BytesIO(
            response if isinstance(response, bytes) else json.dumps(response).encode()
        )
        for response in responses
    ]
    return opener


def successful_management_responses():
    return [
        {"success": True, "data": {"status": False, "root_init": False}},
        {"success": True},
        {"success": True, "data": {"access_token": TEST_TOKEN}},
        {"success": True},
        {"success": True},
        {
            "success": True,
            "data": [
                {"key": "RegisterEnabled", "value": "false"},
                {"key": "PasswordRegisterEnabled", "value": "false"},
            ],
        },
        {"success": True},
        {"success": True, "data": {"status": True, "root_init": True}},
    ]


class DeploymentBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name) / "deployment"
        self.root.mkdir(mode=0o700)

    def run_script(self, name, arguments=(), opener=None, root=None):
        deployment_root = root or self.root
        path_class = type(deployment_root)
        stdout = io.StringIO()
        stderr = io.StringIO()
        chown = mock.Mock()
        error = None
        previous_umask = os.umask(0o077)
        os.umask(previous_umask)

        def redirected_path(*parts, **kwargs):
            if len(parts) == 1 and os.fspath(parts[0]) == "/opt/new-api-dev":
                return deployment_root
            return path_class(*parts, **kwargs)

        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                stack.enter_context(mock.patch("sys.argv", [name, *arguments]))
                stack.enter_context(mock.patch.object(pathlib, "Path", redirected_path))
                stack.enter_context(mock.patch("os.chown", chown))
                stack.enter_context(
                    mock.patch("urllib.request.build_opener", return_value=opener)
                )
                stack.enter_context(
                    mock.patch(
                        "socket.create_connection",
                        side_effect=AssertionError("Network access is forbidden in these tests"),
                    )
                )
                try:
                    runpy.run_path(str(SCRIPT_DIRECTORY / name), run_name="__main__")
                except SystemExit as exception:
                    error = exception
        finally:
            os.umask(previous_umask)
        return error, stdout.getvalue(), stderr.getvalue(), chown

    def test_initialize_generates_distinct_256_bit_secrets_and_private_files(self):
        generated = [str(number) * 64 for number in range(1, 5)]
        with mock.patch("secrets.token_hex", side_effect=generated) as token_hex:
            error, stdout, stderr, chown = self.run_script(
                "initialize.py", ["--redis-uid", "999", "--redis-gid", "999"]
            )

        self.assertIsNone(error)
        self.assertEqual(token_hex.call_args_list, [mock.call(32)] * 4)
        values = dict(
            line.split("=", 1)
            for line in (self.root / "runtime.env").read_text().splitlines()
        )
        pg_password = (self.root / "secrets/postgres_password").read_text()
        redis_lines = (self.root / "secrets/redis.conf").read_text().splitlines()
        redis_password = next(
            line.removeprefix("requirepass ")
            for line in redis_lines
            if line.startswith("requirepass ")
        )
        persisted = [
            pg_password,
            redis_password,
            values["SESSION_SECRET"],
            values["CRYPTO_SECRET"],
        ]
        self.assertEqual(persisted, generated)
        self.assertEqual(len(set(persisted)), 4)
        self.assertEqual(
            values["SQL_DSN"],
            f"postgresql://newapi:{pg_password}@postgres:5432/newapi",
        )
        self.assertEqual(
            values["REDIS_CONN_STRING"], f"redis://:{redis_password}@redis:6379/0"
        )
        for secret in persisted:
            self.assertRegex(secret, r"^[0-9a-f]{64}$")
            self.assertNotIn(secret, stdout + stderr)
        for relative_path in ("runtime.env", "secrets/postgres_password"):
            self.assertEqual(stat.S_IMODE((self.root / relative_path).stat().st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE((self.root / "secrets/redis.conf").stat().st_mode), 0o400
        )
        chown.assert_called_once_with(self.root / "secrets/redis.conf", 999, 999)
        self.assertEqual(values["SESSION_COOKIE_SECURE"], "false")
        self.assertEqual(values["TRUSTED_PROXIES"], "none")
        self.assertEqual(values["GENERATE_DEFAULT_TOKEN"], "false")

    def test_initialize_requires_explicit_non_root_redis_owner_before_writing_secrets(self):
        invalid_arguments = (
            [],
            ["--redis-uid", "999"],
            ["--redis-gid", "999"],
            ["--redis-uid", "0", "--redis-gid", "999"],
            ["--redis-uid", "999", "--redis-gid", "0"],
            ["--redis-uid", "-1", "--redis-gid", "999"],
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments), mock.patch("secrets.token_hex") as token_hex:
                error, stdout, _, chown = self.run_script("initialize.py", arguments)
                self.assertIsNotNone(error)
                self.assertEqual(stdout, "")
                self.assertFalse((self.root / "runtime.env").exists())
                self.assertFalse((self.root / "secrets").exists())
                token_hex.assert_not_called()
                chown.assert_not_called()

    def test_initialize_refuses_to_rotate_existing_runtime_secrets(self):
        runtime = self.root / "runtime.env"
        original = "SESSION_SECRET=existing-unit-test-value\n"
        runtime.write_text(original)
        with mock.patch("secrets.token_hex") as token_hex:
            error, stdout, _, chown = self.run_script(
                "initialize.py", ["--redis-uid", "999", "--redis-gid", "999"]
            )
        self.assertIsNotNone(error)
        self.assertIn("refusing to rotate", str(error))
        self.assertEqual(runtime.read_text(), original)
        self.assertEqual(stdout, "")
        token_hex.assert_not_called()
        chown.assert_not_called()

    def test_admin_refuses_existing_setup_or_root_without_creating_credentials(self):
        for status, root_init in ((True, False), (False, True), (True, True)):
            with self.subTest(status=status, root_init=root_init):
                opener = management_opener([
                    {"success": True, "data": {"status": status, "root_init": root_init}}
                ])
                with mock.patch("secrets.token_urlsafe") as token_urlsafe:
                    error, stdout, stderr, _ = self.run_script(
                        "bootstrap-admin.py", opener=opener
                    )
                self.assertIsNotNone(error)
                self.assertIn("refusing to create or replace", str(error))
                self.assertEqual(opener.open.call_count, 1)
                request = opener.open.call_args.args[0]
                self.assertEqual(request.full_url, "http://127.0.0.1:3000/api/setup")
                self.assertEqual(request.get_method(), "GET")
                self.assertFalse((self.root / "bootstrap-admin.json").exists())
                token_urlsafe.assert_not_called()
                self.assertEqual(stdout + stderr, "")

    def test_admin_private_bootstrap_disables_both_registrations_and_logs_out(self):
        opener = management_opener(successful_management_responses())
        with mock.patch("secrets.token_urlsafe", return_value=TEST_PASSWORD) as token_urlsafe:
            error, stdout, stderr, _ = self.run_script("bootstrap-admin.py", opener=opener)
        self.assertIsNone(error)
        token_urlsafe.assert_called_once_with(32)
        credential_file = self.root / "bootstrap-admin.json"
        credential = json.loads(credential_file.read_text())
        self.assertEqual(credential, {"username": "infoadmin", "password": TEST_PASSWORD})
        self.assertEqual(stat.S_IMODE(credential_file.stat().st_mode), 0o600)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(
            [(request.get_method(), request.selector) for request in requests],
            [
                ("GET", "/api/setup"),
                ("POST", "/api/setup"),
                ("POST", "/api/user/login"),
                ("PUT", "/api/option/"),
                ("PUT", "/api/option/"),
                ("GET", "/api/option/"),
                ("POST", "/api/user/auth/logout"),
                ("GET", "/api/setup"),
            ],
        )
        self.assertTrue(all(request.host == "127.0.0.1:3000" for request in requests))
        setup_payload = json.loads(requests[1].data)
        self.assertEqual(setup_payload["password"], credential["password"])
        self.assertEqual(setup_payload["confirmPassword"], credential["password"])
        self.assertIs(setup_payload["SelfUseModeEnabled"], True)
        self.assertIs(setup_payload["DemoSiteEnabled"], False)
        self.assertEqual(json.loads(requests[2].data), credential)
        self.assertEqual(
            [json.loads(request.data) for request in requests[3:5]],
            [
                {"key": "RegisterEnabled", "value": "false"},
                {"key": "PasswordRegisterEnabled", "value": "false"},
            ],
        )
        for request in requests[3:7]:
            self.assertEqual(request.get_header("Authorization"), "Bearer " + TEST_TOKEN)
        self.assertNotIn(TEST_PASSWORD, stdout + stderr)
        self.assertNotIn(TEST_TOKEN, stdout + stderr)
        self.assertIn("public registration disabled", stdout)
        self.assertIn("bootstrap session logged out", stdout)

    def test_admin_stops_on_rejected_operation_without_claiming_readiness(self):
        for rejected_index in range(1, 7):
            with self.subTest(rejected_index=rejected_index), tempfile.TemporaryDirectory() as directory:
                deployment_root = pathlib.Path(directory)
                responses = successful_management_responses()
                responses[rejected_index] = {
                    "success": False,
                    "message": "sensitive-unit-test-server-response",
                }
                opener = management_opener(responses)
                with mock.patch("secrets.token_urlsafe", return_value=TEST_PASSWORD):
                    error, stdout, stderr, _ = self.run_script(
                        "bootstrap-admin.py", opener=opener, root=deployment_root
                    )
                self.assertIsNotNone(error)
                self.assertIn("Management operation rejected", str(error))
                cleanup_call = 1 if 3 <= rejected_index <= 5 else 0
                self.assertEqual(opener.open.call_count, rejected_index + 1 + cleanup_call)
                if rejected_index >= 3:
                    logout = opener.open.call_args.args[0]
                    self.assertEqual(logout.selector, "/api/user/auth/logout")
                    self.assertEqual(logout.get_method(), "POST")
                self.assertEqual(stdout + stderr, "")
                self.assertNotIn("sensitive-unit-test-server-response", str(error))
                self.assertNotIn(TEST_PASSWORD, str(error))
                self.assertNotIn(TEST_TOKEN, str(error))

    def test_admin_does_not_claim_success_without_confirmed_security_state(self):
        cases = (
            (2, {"success": True, "data": {}}, 3),
            (7, {"success": True, "data": {"status": False}}, 8),
            (
                5,
                {
                    "success": True,
                    "data": [
                        {"key": "RegisterEnabled", "value": "true"},
                        {"key": "PasswordRegisterEnabled", "value": "false"},
                    ],
                },
                7,
            ),
            (5, {"success": True, "data": []}, 7),
        )
        for index, replacement, expected_calls in cases:
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                responses = successful_management_responses()
                responses[index] = replacement
                opener = management_opener(responses)
                with mock.patch("secrets.token_urlsafe", return_value=TEST_PASSWORD):
                    error, stdout, stderr, _ = self.run_script(
                        "bootstrap-admin.py", opener=opener, root=pathlib.Path(directory)
                    )
                self.assertIsNotNone(error)
                self.assertEqual(opener.open.call_count, expected_calls)
                if index == 5:
                    self.assertEqual(
                        opener.open.call_args.args[0].selector,
                        "/api/user/auth/logout",
                    )
                self.assertEqual(stdout + stderr, "")

    def test_admin_redacts_transport_and_invalid_response_failures(self):
        failures = (
            urllib.error.URLError("sensitive-unit-test-network-detail"),
            b"invalid-json-sensitive-unit-test-server-response",
        )
        for failure in failures:
            with self.subTest(failure_type=type(failure).__name__):
                opener = management_opener([failure])
                error, stdout, stderr, _ = self.run_script("bootstrap-admin.py", opener=opener)
                self.assertIsNotNone(error)
                self.assertIn("Management request failed", str(error))
                self.assertNotIn("sensitive-unit-test", str(error))
                self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(stdout + stderr, "")
                self.assertFalse((self.root / "bootstrap-admin.json").exists())


if __name__ == "__main__":
    unittest.main()
