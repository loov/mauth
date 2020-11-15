# appengine example

This example demonstrates how to setup Google authentication on Google AppEngine with using Secret Manager to manage credentials.
This approach avoids requiring people to download credentials to their development computers.

To setup the project:

1. In https://console.cloud.google.com/apis/credentials create new Web Credentials and setup Consent Screen.
2. Download the `credentials.json`.
3. In https://console.cloud.google.com/security/secret-manager add the credentials as a secret. The default name used is `google_oauth2_credentials`. However that can be changed in `app.yaml`.
4. In https://console.cloud.google.com/iam-admin/iam press `Edit` for `App Engine default service account`. Add "Secret Manager Secret Accessor" role to it and restrict it to only `projects/<project_id>/secrets/<secret_name>/versions/latest`.
5. Run `gcloud app deploy` to deploy the example.