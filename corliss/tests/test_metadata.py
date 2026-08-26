from django.test import TestCase, override_settings

from corliss import atproto


@override_settings(PUBLIC_BASE_URL="https://auth.example.test")
class ClientMetadataTests(TestCase):
    def test_metadata_endpoint_is_schema_shaped(self):
        resp = self.client.get("/auth/client-metadata.json")
        self.assertEqual(resp.status_code, 200)
        m = resp.json()
        # client_id IS the metadata URL (atproto requirement).
        self.assertEqual(
            m["client_id"], "https://auth.example.test/auth/client-metadata.json"
        )
        self.assertEqual(m["token_endpoint_auth_method"], "private_key_jwt")
        self.assertEqual(m["token_endpoint_auth_signing_alg"], "ES256")
        self.assertTrue(m["dpop_bound_access_tokens"])
        self.assertEqual(m["application_type"], "web")
        self.assertIn(
            "https://auth.example.test/auth/oauth/callback", m["redirect_uris"]
        )
        self.assertEqual(
            m["jwks_uri"], "https://auth.example.test/.well-known/jwks.json"
        )
        self.assertIn("atproto", m["scope"])
        self.assertIn("authorization_code", m["grant_types"])

    def test_every_requestable_scope_is_declared(self):
        # Regression guard: the PDS authorization server checks a PAR request's
        # scope against what the client declares here, so a term requested but
        # not declared fails login with invalid_scope — exactly what broke login
        # in production once (transition:email requested but not declared).
        #
        # This asserted equality while there was one scope to request. There are
        # now two — members get SCOPE, the service account additionally gets the
        # roster collection so it can write that record — so the property that
        # actually holds is containment, in every direction a login can take.
        resp = self.client.get("/auth/client-metadata.json")
        declared = set(resp.json()["scope"].split())
        for scope in (atproto.SCOPE, atproto.SERVICE_SCOPE):
            self.assertLessEqual(set(scope.split()), declared)

    def test_transition_email_is_declared(self):
        # Without this, PAR fails closed with invalid_scope and login never
        # gets far enough to call fetch_session_email.
        resp = self.client.get("/auth/client-metadata.json")
        self.assertIn("transition:email", resp.json()["scope"].split())
        self.assertIn("transition:email", atproto.SCOPE.split())
