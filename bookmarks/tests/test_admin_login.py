from django.test import TestCase

from bookmarks.tests.helpers import BookmarkFactoryMixin


class AdminLoginTestCase(TestCase, BookmarkFactoryMixin):
    def test_redirects_to_linkding_login(self):
        response = self.client.get("/admin/login/?next=/admin/bookmarks/")

        self.assertRedirects(
            response,
            "/login?next=/admin/bookmarks/",
            fetch_redirect_response=False,
        )

    def test_redirects_to_admin_index_by_default(self):
        response = self.client.get("/admin/login/")

        self.assertRedirects(
            response, "/login?next=/admin/", fetch_redirect_response=False
        )

    def test_admin_login_form_does_not_authenticate(self):
        user = self.setup_superuser()
        user.set_password("test")
        user.save()

        self.client.post(
            "/admin/login/", {"username": user.username, "password": "test"}
        )

        self.assertIsNone(self.client.session.get("_auth_user_id"))

    def test_authenticated_non_staff_user_gets_403(self):
        self.client.force_login(self.setup_user())

        response = self.client.get("/admin/login/?next=/admin/")

        self.assertEqual(403, response.status_code)

    def test_staff_user_on_login_url_redirects_to_admin_index(self):
        self.client.force_login(self.setup_superuser())

        response = self.client.get("/admin/login/?next=/admin/")

        self.assertRedirects(response, "/admin/", fetch_redirect_response=False)

    def test_staff_user_can_access_admin(self):
        self.client.force_login(self.setup_superuser())

        response = self.client.get("/admin/")

        self.assertEqual(200, response.status_code)
