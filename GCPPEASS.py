import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import google.oauth2.credentials
import googleapiclient.discovery
import tqdm
import re
from bs4 import BeautifulSoup

from src.CloudPEASS.cloudpeass import CloudPEASS
from src.sensitive_permissions.gcp import very_sensitive_combinations, sensitive_combinations

GCP_MALICIOUS_RESPONSE_EXAMPLE = """[
    {
        "Title": "Escalate Privileges via Cloud Functions",
        "Description": "With cloudfunctions.functions.create permission, an attacker can deploy malicious functions with high privileges.",
        "Commands": "gcloud functions deploy ..."
    },
    [...]
]"""

GCP_SENSITIVE_RESPONSE_EXAMPLE = """[
    {
        "permission": "cloudfunctions.functions.create",
        "is_very_sensitive": true,
        "is_sensitive": false,
        "description": "Allows deploying Cloud Functions, potentially escalating privileges."
    },
    [...]
]"""


class GCPPEASS(CloudPEASS):
    def __init__(self, credentials, project, folder, org, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path=None):
        self.credentials = credentials
        self.project = project
        self.folder = folder
        self.org = org

        super().__init__(very_sensitive_combos, sensitive_combos, "GCP", not_use_ht_ai, num_threads,
                         GCP_MALICIOUS_RESPONSE_EXAMPLE, GCP_SENSITIVE_RESPONSE_EXAMPLE, out_path)

    def download_gcp_permissions(self):
        base_ref_page = requests.get("https://cloud.google.com/iam/docs/permissions-reference").text
        permissions = re.findall('<td id="([^"]+)"', base_ref_page)
        return permissions

    def check_permissions(self, resource, perms_chunk):
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials)
        req = service.projects().testIamPermissions(resource=resource, body={"permissions": perms_chunk})

        try:
            result = req.execute()
            return result.get("permissions", [])
        except:
            return []

    def list_projects(self):
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials)
        req = service.projects().list()
        try:
            result = req.execute()
            return [proj['projectId'] for proj in result.get('projects', [])]
        except:
            return []

    def list_folders(self):
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials)
        req = service.folders().list()
        try:
            result = req.execute()
            return [folder['name'].split('/')[-1] for folder in result.get('folders', [])]
        except:
            return []

    def list_organizations(self):
        service = googleapiclient.discovery.build("cloudresourcemanager", "v3", credentials=self.credentials)
        req = service.organizations().search(body={})
        try:
            result = req.execute()
            return [org['name'].split('/')[-1] for org in result.get('organizations', [])]
        except:
            return []

    def get_resources_and_permissions(self):
        permissions = self.download_gcp_permissions()
        permissions_chunks = [permissions[i:i+20] for i in range(0, len(permissions), 20)]

        targets = []
        if self.project:
            targets.append(f"projects/{self.project}")
        if self.folder:
            targets.append(f"folders/{self.folder}")
        if self.org:
            targets.append(f"organizations/{self.org}")

        targets.extend([f"projects/{p}" for p in self.list_projects()])
        targets.extend([f"folders/{f}" for f in self.list_folders()])
        targets.extend([f"organizations/{o}" for o in self.list_organizations()])

        found_permissions = []
        lock = Lock()

        def task(target, chunk):
            perms = self.check_permissions(target, chunk)
            with lock:
                found_permissions.append({"id": target, "permissions": perms})

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(task, target, chunk) for target in targets for chunk in permissions_chunks]
            for _ in tqdm.tqdm(as_completed(futures), total=len(futures)):
                pass

        return found_permissions


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GCPPEASS: Enumerate GCP permissions and check for privilege escalations.")

    scope_group = parser.add_mutually_exclusive_group(required=False)
    scope_group.add_argument('--project', help="Project ID")
    scope_group.add_argument('--folder', help="Folder ID")
    scope_group.add_argument('--organization', help="Organization ID")

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--credentials', help="Path to credentials.json")
    auth_group.add_argument('--token', help="Raw access token")

    parser.add_argument('--out', default=None, help="Output JSON file path")
    parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
    parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")

    args = parser.parse_args()

    creds = google.oauth2.credentials.Credentials(args.token.rstrip()) if args.token else \
        google.oauth2.service_account.Credentials.from_service_account_file(
            args.credentials, scopes=["https://www.googleapis.com/auth/cloud-platform"])

    gcp_peass = GCPPEASS(
        creds, args.project, args.folder, args.organization,
        very_sensitive_combinations, sensitive_combinations,
        not_use_ht_ai=args.not_use_hacktricks_ai,
        num_threads=args.threads,
        out_path=args.out
    )
    gcp_peass.run_analysis()