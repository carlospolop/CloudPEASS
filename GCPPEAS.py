import argparse
import requests
import google.oauth2.credentials
import googleapiclient.discovery
import httplib2
import re
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm
from colorama import Fore, Style, init, Back
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp

from src.CloudPEASS.cloudpeass import CloudPEASS, CloudResource
from src.sensitive_permissions.gcp import very_sensitive_combinations, sensitive_combinations
from src.gcp.definitions import NOT_COMPUTE_PERMS, NOT_FUNCTIONS_PERMS, NOT_STORAGE_PERMS, NOT_SA_PERMS, NOT_PROJECT_PERMS, NOT_FOLDER_PERMS, NOT_ORGANIZATION_PERMS


init(autoreset=True)








GCP_MALICIOUS_RESPONSE_EXAMPLE = """[
	{
		"Title": "Escalate Privileges via Compute Engine",
		"Description": "With compute.instances.setIamPolicy permission, an attacker can grant itself a role with the previous permissions and escalate privileges abusing them. Here is an example adding roles/compute.admin to a Service.",
		"Commands": "cat <<EOF > policy.json
bindings:
- members:
  - serviceAccount:$SERVER_SERVICE_ACCOUNT
  role: roles/compute.admin
version: 1
EOF

gcloud compute instances set-iam-policy $INSTANCE policy.json --zone=$ZONE"
		"Permissions": [
			"compute.instances.setIamPolicy"
		],
	},
	[...]
]"""

GCP_SENSITIVE_RESPONSE_EXAMPLE = """[
	{
		"permission": "cloudfunctions.functions.sourceCodeSet",
		"is_very_sensitive": true,
		"is_sensitive": false,
		"description": "An attacker with this permission could modify the code of a Function to ecalate privileges to the SA used by the function."
	},
	[...]
]"""

GCP_CLARIFICATIONS = ""


INVALID_PERMS = {}


class GCPPEASS(CloudPEASS):
	def __init__(self, credentials, extra_token, projects, folders, orgs, sas, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path, billing_project, proxy, print_invalid_perms, dont_get_iam_policies, skip_bruteforce=False, no_ask=False):
		self.credentials = credentials
		self.extra_token = extra_token
		self.projects = [p.strip() for p in projects.split(",")] if projects else []
		self.folders = [f.strip() for f in folders.split(",")] if folders else []
		self.orgs = [o.strip() for o in orgs.split(",")] if orgs else []
		self.sas = [sa.strip() for sa in sas.split(",")] if sas else []
		self.billing_project = billing_project
		self.email = ""
		self.is_sa = False
		self.groups = []
		self.print_invalid_perms = print_invalid_perms
		self.dont_get_iam_policies = dont_get_iam_policies
		self.skip_bruteforce = skip_bruteforce
		self.no_ask = no_ask
		
		if proxy:
			proxy = proxy.split("//")[-1] # Porotocol not needed
			self.proxy_host = proxy.split(":")[0]
			self.proxy_port = int(proxy.split(":")[1])
		else:
			self.proxy_host = None
			self.proxy_port = None
		
		self.all_gcp_perms = self.download_gcp_permissions()

		super().__init__(very_sensitive_combos, sensitive_combos, "GCP", not_use_ht_ai, num_threads,
						 GCP_MALICIOUS_RESPONSE_EXAMPLE, GCP_SENSITIVE_RESPONSE_EXAMPLE, GCP_CLARIFICATIONS, out_path)

	def download_gcp_permissions(self):
		print(f"{Fore.BLUE}Downloading permissions...")
		base_ref_page = requests.get("http://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/gcp/permissions.json").text
		permissions = list(set(json.loads(base_ref_page).keys()))
		print(f"{Fore.GREEN}Gathered {len(permissions)} GCP permissions to check")
		return permissions

	def authed_http(self):
		"""
		Returns an authorized http object to make requests to the GCP API.
		"""
		if self.proxy_host and self.proxy_port:
			proxy_info = httplib2.ProxyInfo(
				proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
				proxy_host=self.proxy_host,
				proxy_port=self.proxy_port,
			)
			theHttp = httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=True)
			return AuthorizedHttp(self.credentials, http=theHttp)
		else:
			return AuthorizedHttp(self.credentials)









	############################
	### LISTING GCP SERVICES ###
	############################

	def list_projects(self):
		req = googleapiclient.discovery.build("cloudresourcemanager", "v1", http=self.authed_http()).projects().list()
		try:
			result = req.execute()
			return [proj['projectId'] for proj in result.get('projects', [])]
		except:
			return []

	def list_folders(self):
		req = googleapiclient.discovery.build("cloudresourcemanager", "v2", http=self.authed_http()).folders().search(body={})
		try:
			result = req.execute()
			return [folder['name'].split('/')[-1] for folder in result.get('folders', [])]
		except:
			return []

	def list_organizations(self):
		req = googleapiclient.discovery.build("cloudresourcemanager", "v1", http=self.authed_http()).organizations().search(body={})
		try:
			result = req.execute()
			return [org['name'].split('/')[-1] for org in result.get('organizations', [])]
		except:
			return []

	def list_vms(self, project):
		try:
			request = googleapiclient.discovery.build("compute", "v1", http=self.authed_http()).instances().aggregatedList(project=project)
			vms = []
			while request is not None:
				response = request.execute()
				for zone, instances_scoped_list in response.get('items', {}).items():
					for instance in instances_scoped_list.get('instances', []):
						# Construct a unique target identifier for the VM
						zone_name = instance.get('zone', '').split('/')[-1]
						target_id = f"projects/{project}/zones/{zone_name}/instances/{instance['name']}"
						vms.append(target_id)
				request = googleapiclient.discovery.build("compute", "v1", http=self.authed_http()).instances().aggregatedList_next(previous_request=request, previous_response=response)
			return vms
		except Exception:
			return []

	def list_functions(self, project):
		try:
			parent = f"projects/{project}/locations/-"
			response = googleapiclient.discovery.build("cloudfunctions", "v1", http=self.authed_http()).projects().locations().functions().list(parent=parent).execute()
			functions = []
			for function in response.get('functions', []):
				# The function name is already fully qualified
				functions.append(function['name'])
			return functions
		except Exception:
			return []

	def list_storages(self, project):
		try:
			response = googleapiclient.discovery.build("storage", "v1", http=self.authed_http()).buckets().list(project=project).execute()
			buckets = []
			for bucket in response.get('items', []):
				# Construct a unique target identifier for the Storage bucket
				buckets.append(f"projects/{project}/storage/{bucket['name']}")
			return buckets
		except Exception:
			return []
	
	def list_service_accounts(self, project):
		try:
			service = googleapiclient.discovery.build("iam", "v1", http=self.authed_http())
			# The service account resource name will be like "projects/{project}/serviceAccounts/{email}"
			response = service.projects().serviceAccounts().list(name=f"projects/{project}").execute()
			accounts = []
			for account in response.get('accounts', []):
				accounts.append(account['name'])  # Use the full resource name
			return accounts
		except Exception as e:
			print(f"{Fore.RED}Error listing service accounts for project {project}: {e}")
			return []
	






	######################################
	### GET IAM POLICIES FOR RESOURCES ###
	######################################

	def get_iam_policy(self, resource_id):
		"""
		Retrieve the IAM policy for the specified resource.
		"""

		try:
			if resource_id.startswith("projects/"):
				service = googleapiclient.discovery.build("cloudresourcemanager", "v1", http=self.authed_http())
				request = service.projects().getIamPolicy(resource=resource_id.split("/")[1], body={})
			elif resource_id.startswith("folders/"):
				service = googleapiclient.discovery.build("cloudresourcemanager", "v2", http=self.authed_http())
				request = service.folders().getIamPolicy(resource=resource_id, body={})
			elif resource_id.startswith("organizations/"):
				service = googleapiclient.discovery.build("cloudresourcemanager", "v1", http=self.authed_http())
				request = service.organizations().getIamPolicy(resource=resource_id, body={})
			elif "/functions/" in resource_id:
				service = googleapiclient.discovery.build("cloudfunctions", "v1", http=self.authed_http())
				request = service.projects().locations().functions().getIamPolicy(resource=resource_id)
			elif "/instances/" in resource_id:
				# Compute Engine instances do not support getIamPolicy
				return None
			elif "/storage/" in resource_id:
				service = googleapiclient.discovery.build("storage", "v1", http=self.authed_http())
				bucket_name = resource_id.split("/")[-1]
				request = service.buckets().getIamPolicy(bucket=bucket_name)
			elif "/serviceAccounts/" in resource_id:
				service = googleapiclient.discovery.build("iam", "v1", http=self.authed_http())
				request = service.projects().serviceAccounts().getIamPolicy(resource=resource_id)
			else:
				return None

			if self.billing_project:
				request.headers["X-Goog-User-Project"] = self.billing_project

			response = request.execute()
			return response
		except Exception as e:
			if "403" in str(e):
				print(f"{Fore.RED}Permission denied to get IAM policy for {resource_id}.")
			else:
				print(f"{Fore.RED}Failed to get IAM policy for {resource_id}: {e}")
			return None
	
	def get_permissions_from_role(self, role_name):
		"""
		Retrieve the list of permissions associated with a given IAM role.
		"""
		try:
			if role_name.startswith("roles/"):
				# Predefined role
				service = googleapiclient.discovery.build("iam", "v1", credentials=self.credentials)
				request = service.roles().get(name=role_name)
			elif role_name.startswith("projects/"):
				# Project-level custom role
				service = googleapiclient.discovery.build("iam", "v1", credentials=self.credentials)
				request = service.projects().roles().get(name=role_name)
			elif role_name.startswith("organizations/"):
				# Organization-level custom role
				service = googleapiclient.discovery.build("iam", "v1", credentials=self.credentials)
				request = service.organizations().roles().get(name=role_name)
			else:
				print(f"{Fore.RED}Unsupported role format: {role_name}")
				return []

			response = request.execute()
			return response.get("includedPermissions", [])
		except Exception as e:
			if "Identity and Access Management (IAM) API has not been used" in str(e):
				print(f"{Fore.RED}IAM API is not enabled. Please enable it in the project or set a billing project that has IAM API enabled.")
				return "Stop"
			print(f"{Fore.RED}Failed to retrieve permissions for role {role_name}: {e}")
			return []








	###############################
	### BRUTEFORCE PERMISSIONS ####
	###############################
	
	def get_relevant_permissions(self, res_type=None):
		if res_type.lower() == "vm":
			return [p for p in self.all_gcp_perms if p.startswith("compute") and p not in NOT_COMPUTE_PERMS]
		elif res_type.lower() == "function":
			return [p for p in self.all_gcp_perms if p.startswith("cloudfunctions") and p not in NOT_FUNCTIONS_PERMS]
		elif res_type.lower() == "storage":
			return [p for p in self.all_gcp_perms if p.startswith("storage") and p not in NOT_STORAGE_PERMS]
		elif res_type.lower() == "service_account":
			return [p for p in self.all_gcp_perms if p.startswith("iam.serviceAccounts") and p not in NOT_SA_PERMS]
		elif res_type.lower() == "project":
			return [p for p in self.all_gcp_perms if p not in NOT_PROJECT_PERMS]
		elif res_type.lower() == "folder":
			return [p for p in self.all_gcp_perms if p not in NOT_FOLDER_PERMS]
		elif res_type.lower() == "organization":
			return [p for p in self.all_gcp_perms if p not in NOT_ORGANIZATION_PERMS]
		else:
			return self.all_gcp_perms
	
	def get_permissions_check_request(self, resource_id, perms):
		"""
		Given a resource ID and a list of permissions, return the request to check permissions.
		"""

		req = None

		if "/functions/" in resource_id:
			req = googleapiclient.discovery.build("cloudfunctions", "v1", http=self.authed_http()).projects().locations().functions().testIamPermissions(
				resource=resource_id,
				body={"permissions": perms},
			)
		elif "/instances/" in resource_id:
			req = googleapiclient.discovery.build("compute", "v1", http=self.authed_http()).instances().testIamPermissions(
				project=resource_id.split("/")[1],
				resource=resource_id.split("/")[-1],
				zone=resource_id.split("/")[3],
				body={"permissions": perms},
			)
		elif "/storage/" in resource_id:
			req = googleapiclient.discovery.build("storage", "v1", http=self.authed_http()).buckets().testIamPermissions(
				bucket=resource_id.split("/")[-1],
				permissions=perms,
			)
		elif "/serviceAccounts/" in resource_id:
			req = googleapiclient.discovery.build("iam", "v1", http=self.authed_http()) \
				.projects().serviceAccounts().testIamPermissions(
					resource=resource_id,
					body={"permissions": perms}
				)
		elif resource_id.startswith("projects/"):
			req = googleapiclient.discovery.build("cloudresourcemanager", "v3", http=self.authed_http()).projects().testIamPermissions(
				resource=resource_id,
				body={"permissions": perms},
			)
		elif resource_id.startswith("folders/"):
			req = googleapiclient.discovery.build("cloudresourcemanager", "v3", http=self.authed_http()).folders().testIamPermissions(
				resource=resource_id,
				body={"permissions": perms},
			)
		elif resource_id.startswith("organizations/"):
			req = googleapiclient.discovery.build("cloudresourcemanager", "v3", http=self.authed_http()).organizations().testIamPermissions(
				resource=resource_id,
				body={"permissions": perms},
			)
		else:
			print(f"{Fore.RED}Unsupported resource type: {resource_id}")
		
		if self.billing_project:
			req.headers["X-Goog-User-Project"] = self.billing_project
		
		return req

	def can_check_permissions(self, resource_id, perms):
		"""
		Test if the service to test if user has the indicated permissions on a resource is enabled.
		"""

		req = self.get_permissions_check_request(resource_id, perms)
		if not req:
			raise ValueError(f"Unsupported resource type: {resource_id}")

		try:
			req.execute()
			return True
		except googleapiclient.errors.HttpError as e:
			if "Cloud Resource Manager API has not been used" in str(e):
				if self.billing_project:
					if self.no_ask:
						user_input = 'n'
					else:
						user_input = input(f"{Fore.RED}Cloudresourcemanager found disabled with billing project {self.billing_project}. Do you want to try without it? (Y/n): ")
					if user_input.lower() != "n":
						self.billing_project = None
						return self.can_check_permissions(resource_id, perms)
				
				else:
					print(f"{Fore.RED}Cloud Resource Manager API is disabled.")
					print(f"{Fore.YELLOW}You could try to give {self.email} the role 'roles/serviceusage.serviceUsageConsumer' in a project controlled by you with that API enabled and pass it with the argument --billing-account.{Fore.RESET}\n")
					if self.email.endswith("iam.gserviceaccount.com"):
						project = self.email.split("@")[1].split(".")[0]
					elif resource_id.startswith("projects/"):
						project = resource_id.split("/")[1]
					else:
						print(f"{Fore.RED}Could not determine project to enable Cloud Resource Manager API. Something went wrong...")
						return False
					
					if self.no_ask:
						user_input = 'n'
					else:
						user_input = input(f"{Fore.YELLOW}Do you want to try to enable it in project {project}? [y/N]: {Fore.WHITE}")
					if user_input.lower() == 'y':
						print(f"{Fore.YELLOW}Trying to enable Cloud Resource Manager API...")
						# Attempt to enable the API
						try:
							googleapiclient.discovery.build("serviceusage", "v1", http=self.authed_http()).services().enable(
								name=f"projects/{project}/services/cloudresourcemanager.googleapis.com"
							).execute()
							print(f"{Fore.GREEN}Enabled Cloud Resource Manager API for {project}.{Fore.RESET} Sleeping 60s to allow the API to be enabled.")
							time.sleep(60)
							can_bf_permissions = self.can_check_permissions(resource_id, perms)
							if not can_bf_permissions:
								print(f"{Fore.RED}Failed to enable Cloud Resource Manager API for {project}. Exiting...")
								return False
							else:
								print(f"{Fore.GREEN}Confirmed, Cloud Resource Manager API was enabled for {project}.")
								return True
						except Exception as e:
							print(f"{Fore.RED}Failed to enable Cloud Resource Manager API: {e}")


				return False
		
		except Exception as e:
			print("Error:")
			print(e)

		return True

	def check_permissions(self, resource_id, perms, verbose=False):
		"""
		Test if the user has the indicated permissions on a resource.

		Supported resource types:
		- projects
		- folders
		- organizations
		- functions
		- vms
		- storage
		- Service account
		"""

		have_perms = []

		req = self.get_permissions_check_request(resource_id, perms)
		if not req:
			return have_perms

		try:
			returnedPermissions = req.execute()
			have_perms = returnedPermissions.get("permissions", [])
		except googleapiclient.errors.HttpError as e:			
			# If a permission is reported as invalid, remove it and retry
			retry = False
			for perm in perms.copy():
				if " " + perm + " " in str(e):
					retry = True
					perms.remove(perm)
					INVALID_PERMS[resource_id] = INVALID_PERMS.get(resource_id, []) + [perm]
			
			if retry:
				return self.check_permissions(resource_id, perms, verbose)
		
		except Exception as e:
			print("Error:")
			print(e)

		if have_perms and verbose:
			print(f"Found: {have_perms}")

		return have_perms








	#########################################
	### GETTING RESOURCES AND PERMISSIONS ###
	#########################################

	def get_resources_and_permissions(self):
		"""
		- Get a list of initial resources
		- For each project, get the VMs, Cloud Functions, Storage buckets and Service Accounts
		- For each resource, get the IAM policy and permissions
		- For each resource, brute-force the permissions
		- Return the list of resources and permissions of the current user
		"""
		

		### Build a list of initial targets with type information ###

		targets = []
		print("Listing projects, folders, and organizations...")

		if self.email.endswith("iam.gserviceaccount.com"):
			sa_project = self.email.split("@")[1].split(".")[0]
			targets.append({"id": f"projects/{sa_project}", "type": "project"})

		if self.projects: # It's important that  project is the first thing to check
			for proj in self.projects:
				targets.append({"id": f"projects/{proj}", "type": "project"})
		
		if self.folders:
			for folder in self.folders:
				if not folder.isdigit():
					print(f"{Fore.RED}Folder {folder} is not a number. Please indicate the folder ID.")
					exit(1)
				targets.append({"id": f"folders/{folder}", "type": "folder"})
		
		if self.orgs:
			for org in self.orgs:
				if not org.isdigit():
					print(f"{Fore.RED}Organization {org} is not a number. Please indicate the organization ID.")
					exit(1)
				targets.append({"id": f"organizations/{org}", "type": "organization"})
		
		if self.sas:
			for sa in self.sas:
				if not "@" in sa:
					print(f"{Fore.RED}Service account {sa} is not an email. Please indicate the service account email.")
					exit(1)
				sa_project = sa.split("@")[1].split(".")[0]
				if sa_project not in self.projects:
					targets.append({"id": f"projects/{sa_project}", "type": "project"})
				targets.append({"id": f"projects/{sa_project}/serviceAccounts/{sa}", "type": "service_account"})

		for proj in self.list_projects():
			targets.append({"id": f"projects/{proj}", "type": "project"})
		for folder in self.list_folders():
			targets.append({"id": f"folders/{folder}", "type": "folder"})
		for org in self.list_organizations():
			targets.append({"id": f"organizations/{org}", "type": "organization"})

		### For each project, add VMs, Cloud Functions, and Storage buckets ###
		# Track which projects will be enumerated for sub-resources
		projects_to_enumerate = []
		for proj in self.list_projects():
			projects_to_enumerate.append(proj)
		
		print("Trying to list VMs, Cloud Functions, Storage buckets and Service Accounts on each project...")
		def process_project(proj):
			local_targets = []
			for vm in self.list_vms(proj):
				local_targets.append({"id": vm, "type": "vm", "project": proj})
			for func in self.list_functions(proj):
				local_targets.append({"id": func, "type": "function", "project": proj})
			for bucket in self.list_storages(proj):
				local_targets.append({"id": bucket, "type": "storage", "project": proj})
			for sa in self.list_service_accounts(proj):
				local_targets.append({"id": sa, "type": "service_account", "project": proj})
			return local_targets

		# Process projects concurrently using a thread pool
		with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
			futures = {executor.submit(process_project, proj): proj for proj in projects_to_enumerate}
			for future in tqdm(as_completed(futures), total=len(futures), desc="Processing projects"):
				targets.extend(future.result())
		
		# Remove duplicates from the targets list
		final_targets = []
		known_targets = set()
		for t in targets:
			final_id = t["id"] + t["type"]
			if final_id not in known_targets:
				known_targets.add(final_id)
				final_targets.append(t)
		targets = final_targets



		### Start looking for IAM policies and permissions ###
		found_permissions = []
		lock = Lock()
		admin_orgs = set()  # Track organizations with admin access
		admin_folders = set()  # Track folders with admin access
		admin_projects = set()  # Track projects with admin access

		def process_target_iam(target, inherited_admin=False):
			# If already known to be admin via inheritance, mark as admin without checking
			if inherited_admin:
				return CloudResource(
					resource_id=target["id"],
					name=target["id"].split("/")[-1] if len(target["id"].split("/")) > 2 else target["id"],
					resource_type=target["type"],
					permissions=[],  # Don't enumerate individual permissions for inherited admin
					deny_perms=[],
					is_admin=True
				)
			
			# Attempt to retrieve IAM policy
			policy = self.get_iam_policy(target["id"])
			collected = []
			is_admin_by_role = False

			if policy and "bindings" in policy:
				for binding in policy["bindings"]:
					members = binding.get("members", [])
					# Check if the user is in the members list
					## If email in the members list
					## Is not SA and the organzation ppal is in the members list
					## If group in the members list
					for member in members:
						affected = False
						member = member.lower()
						if self.email.lower() in member:
							affected = True
						
						elif "group:" in member and self.groups:
							if any(g.lower() in member.lower() for g in self.groups):
								affected = True
						
						elif member.startswith("organizations/") and not self.is_sa:
								affected = True

						if affected:
							role = binding.get("role", "")
							
							# Check if role is a direct admin role
							if target["type"] == "organization" and role.lower() in ["roles/owner", "roles/resourcemanager.organizationadmin"]:
								is_admin_by_role = True
							elif target["type"] == "folder" and role.lower() in ["roles/owner", "roles/resourcemanager.folderadmin"]:
								is_admin_by_role = True
							elif target["type"] == "project" and role.lower() in ["roles/owner", "roles/editor"]:
								is_admin_by_role = True
							
							permissions = self.get_permissions_from_role(role)
							if permissions == "Stop":
								break
							collected.extend(permissions)
			
			# Check if user has admin access (either by role or by permissions)
			collected_unique = list(set(collected))
			is_admin = is_admin_by_role or self._is_admin_gcp(collected_unique, target["type"])
			
			# Track admin resources to skip sub-resources based on hierarchy
			if is_admin:
				with lock:
					if target["type"] == "organization":
						org_id = target["id"].split("/")[-1]
						admin_orgs.add(org_id)
					elif target["type"] == "folder":
						folder_id = target["id"].split("/")[-1]
						admin_folders.add(folder_id)
					elif target["type"] == "project":
						project_id = target["id"].split("/")[-1]
						admin_projects.add(project_id)

			return CloudResource(
				resource_id=target["id"],
				name=target["id"].split("/")[-1] if len(target["id"].split("/")) > 2 else target["id"],
				resource_type=target["type"],
				permissions=collected_unique,
				deny_perms=[],
				is_admin=is_admin
			)
		# Process IAM policies in hierarchical order to detect inherited admin access
		if not self.dont_get_iam_policies:
			# Step 1: Check organizations first
			org_targets = [t for t in targets if t["type"] == "organization"]
			if org_targets:
				print("Checking IAM policies for organizations...")
				with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
					futures = {executor.submit(process_target_iam, target, False): target for target in org_targets}
					for future in tqdm(as_completed(futures), total=len(futures), desc="Checking org IAM policies"):
						res = future.result()
						with lock:
							found_permissions.append(res)
			
			# Step 2: Check folders (could inherit from admin orgs)
			folder_targets = [t for t in targets if t["type"] == "folder"]
			if folder_targets:
				print("Checking IAM policies for folders...")
				with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
					futures = {executor.submit(process_target_iam, target, False): target for target in folder_targets}
					for future in tqdm(as_completed(futures), total=len(futures), desc="Checking folder IAM policies"):
						res = future.result()
						with lock:
							found_permissions.append(res)
			
			# If org admin detected, skip everything else
			if admin_orgs:
				print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
				print(f"{Fore.RED}{Back.YELLOW}  ORGANIZATION ADMINISTRATOR DETECTED                                           {Style.RESET_ALL}")
				print(f"{Fore.RED}{Back.YELLOW}  User is admin of {len(admin_orgs)} organization(s): {', '.join(admin_orgs)}{' '*(36-len(', '.join(admin_orgs)))}{Style.RESET_ALL}")
				print(f"{Fore.RED}{Back.YELLOW}  Skipping enumeration of all {len([t for t in targets if t['type'] in ['folder', 'project']]) + len([t for t in targets if t['type'] not in ['organization', 'folder', 'project']])} folders, projects, and sub-resources{' '*(12)}{Style.RESET_ALL}")
				print(f"{Fore.RED}{Back.YELLOW}  (Organization admin has full access to everything in the org)                 {Style.RESET_ALL}")
				print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
				# Mark all projects as admin without checking them
				for t in targets:
					if t["type"] in ["project", "folder"]:
						found_permissions.append(CloudResource(
							resource_id=t["id"],
							name=t["id"].split("/")[-1] if "/" in t["id"] else t["id"],
							resource_type=t["type"],
							permissions=[],
							deny_perms=[],
							is_admin=True
						))
						if t["type"] == "project":
							admin_projects.add(t["id"].split("/")[-1])
			else:
				# Step 3: Check projects - mark as admin if under admin org/folder
				project_targets = [t for t in targets if t["type"] == "project"]
				if project_targets:
					print("Checking IAM policies for projects...")
					if admin_folders:
						print(f"{Fore.YELLOW}Note: User is admin of {len(admin_folders)} folder(s), projects may inherit admin access")
					
					with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
						futures = {}
						for target in project_targets:
							# Check directly since no org admin
							inherited = False
							futures[executor.submit(process_target_iam, target, inherited)] = target
						
						for future in tqdm(as_completed(futures), total=len(futures), desc="Checking project IAM policies"):
							res = future.result()
							with lock:
								found_permissions.append(res)
								# Track if project is admin via inheritance
								if res.is_admin:
									project_id = res.id.split("/")[-1]
									admin_projects.add(project_id)
				
				# Step 4: Check sub-resources (VMs, functions, etc.) - skip if under admin project
				subresource_targets = [t for t in targets if t["type"] not in ["organization", "folder", "project"]]
				if subresource_targets:
					# Filter out sub-resources under admin projects
					if admin_projects:
						original_count = len(subresource_targets)
						non_admin_subresources = [t for t in subresource_targets if not (t.get("project") and t["project"] in admin_projects)]
						admin_subresources = [t for t in subresource_targets if t.get("project") and t["project"] in admin_projects]
						
						if admin_subresources:
							print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
							print(f"{Fore.RED}{Back.YELLOW}  PROJECT ADMINISTRATOR DETECTED                                                {Style.RESET_ALL}")
							print(f"{Fore.RED}{Back.YELLOW}  User is admin of {len(admin_projects)} project(s): {', '.join(list(admin_projects)[:3])}{('...' if len(admin_projects) > 3 else '')}{' '*(40-len(', '.join(list(admin_projects)[:3])))}{Style.RESET_ALL}")
							print(f"{Fore.RED}{Back.YELLOW}  Skipping enumeration of {len(admin_subresources)} sub-resources from admin projects{' '*(23)}{Style.RESET_ALL}")
							print(f"{Fore.RED}{Back.YELLOW}  (Project admin has full access to all resources in the project)              {Style.RESET_ALL}")
							print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
							
							# Add admin sub-resources without checking
							for t in admin_subresources:
								found_permissions.append(CloudResource(
									resource_id=t["id"],
									name=t["id"].split("/")[-1] if "/" in t["id"] else t["id"],
									resource_type=t["type"],
									permissions=[],
									deny_perms=[],
									is_admin=True
								))
						
						subresource_targets = non_admin_subresources
					
					if subresource_targets:
						print(f"Checking IAM policies for {len(subresource_targets)} sub-resources...")
						with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
							futures = {}
							for target in subresource_targets:
								# These are sub-resources from non-admin projects
								futures[executor.submit(process_target_iam, target, False)] = target
							
							for future in tqdm(as_completed(futures), total=len(futures), desc="Checking sub-resource IAM policies"):
								res = future.result()
								with lock:
									found_permissions.append(res)
		# Filter out resources for bruteforce phase based on admin access hierarchy
		# Note: Org admin already handled above, targets already filtered
		
		if admin_orgs:
			# Already handled - keep only orgs for bruteforce
			targets = [t for t in targets if t["type"] == "organization"]
		elif admin_folders:
			print(f"{Fore.YELLOW}Folder administrator detected on {len(admin_folders)} folder(s): {', '.join(admin_folders)}")
			print(f"{Fore.YELLOW}Skipping all projects and sub-resources under admin folders")
			# Keep orgs, admin folders, and projects/resources NOT under admin control
			# Since we don't track folder→project hierarchy easily, we conservatively skip all projects
			# when ANY folder admin is detected (user can specify specific projects if needed)
			original_count = len(targets)
			targets = [t for t in targets if t["type"] in ["organization", "folder"]]
			skipped_count = original_count - len(targets)
			if skipped_count > 0:
				print(f"{Fore.GREEN}Skipped {skipped_count} project(s) and sub-resource(s)")
		elif admin_projects:
			print(f"{Fore.YELLOW}Project administrator detected on {len(admin_projects)} project(s): {', '.join(admin_projects)}")
			print(f"{Fore.YELLOW}Skipping sub-resources for admin projects")
			original_count = len(targets)
			# Skip sub-resources (vm, function, storage, service_account) from admin projects
			targets = [t for t in targets if not (t.get("project") and t["project"] in admin_projects and t["type"] not in ["project", "folder", "organization"])]
			skipped_count = original_count - len(targets)
			if skipped_count > 0:
				print(f"{Fore.GREEN}Skipped {skipped_count} sub-resource(s) from admin projects")

		# Function to process each target resource for bruteforcing
		def process_target(target):
			# Get relevant permissions based on target type
			relevant_perms = self.get_relevant_permissions(target["type"])
			# Split permissions into chunks of 20
			perms_chunks = [relevant_perms[i:i+20] for i in range(0, len(relevant_perms), 20)]
			collected = []

			# Use a thread pool to process each permission chunk concurrently
			with ThreadPoolExecutor(max_workers=5) as executor:
				# Submit tasks for each chunk
				futures = {executor.submit(self.check_permissions, target["id"], chunk): chunk for chunk in perms_chunks}
				# Iterate over completed futures with a progress bar
				for future in tqdm(as_completed(futures), total=len(futures), desc=f"BFing permissions for {target['id']}", leave=False):
					result = future.result()
					collected.extend(result)

			# Check if user has admin access
			is_admin = self._is_admin_gcp(collected, target["type"])

			return CloudResource(
				resource_id=target["id"],
				name=target["id"].split("/")[-1] if len(target["id"].split("/")) > 2 else target["id"],
				resource_type=target["type"],
				permissions=collected,
				deny_perms=[],
				is_admin=is_admin
			)

		### Start bruteforcing permissions ###
		
		# Check if user has admin/owner access - if so, skip bruteforcing
		has_admin = False
		admin_resources = []
		for entry in found_permissions:
			# Convert CloudResource to dict if needed
			if isinstance(entry, CloudResource):
				entry_dict = entry.to_dict()
			else:
				entry_dict = entry
			
			if entry_dict.get("is_admin", False):
				has_admin = True
				admin_resources.append({
					"type": entry_dict["type"],
					"name": entry_dict["name"]
				})
		
		# If admin detected, show summary and skip bruteforcing
		if has_admin:
			# Group by type
			by_type = {}
			for res in admin_resources:
				res_type = res["type"]
				if res_type not in by_type:
					by_type[res_type] = []
				by_type[res_type].append(res["name"])
			
			print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
			print(f"{Fore.RED}{Back.YELLOW}  ADMINISTRATOR ACCESS DETECTED - Skipping bruteforce                          {Style.RESET_ALL}")
			for res_type, names in by_type.items():
				if len(names) <= 3:
					names_str = ', '.join(names)
				else:
					names_str = f"{', '.join(names[:3])}... ({len(names)} total)"
				print(f"{Fore.RED}{Back.YELLOW}  - {len(names)} {res_type}(s): {names_str}{' '*(60-len(f'{len(names)} {res_type}(s): {names_str}'))}{Style.RESET_ALL}")
			print(f"{Fore.RED}{Back.YELLOW}{'='*80}{Style.RESET_ALL}")
			return found_permissions
		if any(p for entry in found_permissions for p in (entry.to_dict() if isinstance(entry, CloudResource) else entry)["permissions"] if p):
			if self.skip_bruteforce:
				return found_permissions
			if self.no_ask:
				user_input = 'y'
			else:
				user_input = input(f"{Fore.YELLOW}Permissions were found accessing the IAM policies. Do you want to continue bruteforcing permissions? [Y/n]: {Fore.WHITE}")
			if user_input.lower() == 'n':
				return found_permissions
			
		# Check if the user has permissions to check the permissions
		if len(targets) == 0:
			return found_permissions
			
		relevant_perms = self.get_relevant_permissions(targets[0]["type"])
		perms_chunks = [relevant_perms[i:i+20] for i in range(0, len(relevant_perms), 20)]
		# Just pass some permissions to check if the API is enabled
		can_bf_permissions = self.can_check_permissions(targets[0]["id"], perms_chunks[0])				
		if can_bf_permissions:
			with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
				futures = {executor.submit(process_target, target): target for target in targets}
				for future in tqdm(as_completed(futures), total=len(futures), desc="Bruteforcing permissions"):
					res = future.result()
					with lock:
						found_permissions.append(res)

		if self.print_invalid_perms and INVALID_PERMS:
			print(f"{Fore.YELLOW}Invalid permissions found:")
			for resource, perms in INVALID_PERMS.items():
				print(f"{Fore.BLUE}{resource}: {', '.join(perms)}")

		return found_permissions

	def _is_admin_gcp(self, permissions, resource_type):
		"""
		Check if the permissions indicate admin/owner access in GCP.
		Returns True if user has Owner-like access.
		Only checks for project, folder, and organization resources.
		"""
		# Only check admin for high-level resources
		if resource_type not in ["project", "folder", "organization"]:
			return False
		
		perms_str = [str(p).lower() for p in permissions]

		if resource_type == "project":
			admin_perms = ["resourcemanager.projects.setiampolicy", "resourcemanager.projects.delete"]
		elif resource_type == "folder":
			admin_perms = ["resourcemanager.folders.setiampolicy", "resourcemanager.folders.delete"]
		elif resource_type == "organization":
			admin_perms = ["resourcemanager.organizations.setiampolicy", "resourcemanager.organizations.delete"]
		
		if all(ap in perms_str for ap in admin_perms):
			return True
		
		return False
	





















	####################################
	### WHOAMI, DRIVE AND GMAIL INFO ###
	####################################
	
	def print_whoami_info(self, use_extra=False):
		"""
		From the token, get the current user information to identify the context of the permissions and scopes.
		"""
		
		user_info = {
			"email": None,
			"expires_in": None,
			"audience": None,
			"scopes": []
		}

		token = None
		if use_extra:
			token = self.extra_token
		else:
			token = self.credentials.token
			if not token: # Then SA json creds
				user_info["email"] = self.credentials.service_account_email
				user_info["scopes"] = self.credentials.scopes

		if token:
			resp = requests.post(
				"https://www.googleapis.com/oauth2/v3/tokeninfo",
				headers={"Content-Type": "application/x-www-form-urlencoded"},
				data={"access_token": token}  # Assuming you have a valid access token
			)
			if resp.status_code != 200:
				print(f"{Fore.RED}Error fetching user info. Token or credentials are invalid.")
				exit(1)
			
			user_info = resp.json()
		if "email" in user_info and user_info["email"]:
			self.email = user_info["email"]
			self.is_sa = user_info["email"].endswith("iam.gserviceaccount.com")
			if self.is_sa:
				msg = f"{Fore.BLUE}Current user: {Fore.WHITE}{user_info['email']} {Fore.CYAN}(Service Account)"
			else:
				msg = f"{Fore.BLUE}Current user: {Fore.WHITE}{user_info['email']} (Not Service Account)"
				self.groups = self.get_user_groups()
				if self.groups:
					msg += f"\n{Fore.BLUE}User groups: {Fore.WHITE}{', '.join([g for g in self.groups if g])}"

			print(msg)
		
		if "expires_in" in user_info and user_info["expires_in"]:
			expires_in = user_info["expires_in"]
			print(f"{Fore.BLUE}Token expires in: {Fore.WHITE}{expires_in} seconds")
		
		if "audience" in user_info and user_info["audience"]:
			audience = user_info["audience"]
			print(f"{Fore.BLUE}Token audience: {Fore.WHITE}{audience}")
		
		scopes = []
		if "scope" in user_info and user_info["scope"]:
			scopes = user_info["scope"].split()
			print(f"{Fore.BLUE}Scopes: {Fore.WHITE}{', '.join(scopes)}")
		
		if "scopes" in user_info and user_info["scopes"]:
			scopes = user_info["scopes"]
			print(f"{Fore.BLUE}Scopes: {Fore.WHITE}{', '.join(scopes)}")
		
		if any("/gmail" in s for s in scopes):
			print(f"{Fore.GREEN}Note: You have Gmail API access.")
			if self.no_ask:
				user_input = 'n'
			else:
				user_input = input(f"{Fore.YELLOW}Do you want to list emails? [Y/n]: {Fore.WHITE}")
			if user_input.lower() != 'n':
				self.list_gmail_emails(google.oauth2.credentials.Credentials(token))
		
		if any("/drive" in s for s in scopes):
			print(f"{Fore.GREEN}Note: You have Drive API access.")
			if self.no_ask:
				user_input = 'n'
			else:
				user_input = input(f"{Fore.YELLOW}Do you want to list files in Google Drive? [Y/n]: {Fore.WHITE}")
			if user_input.lower() != 'n':
				self.list_drive_files(google.oauth2.credentials.Credentials(token))
		
		if self.extra_token and token != self.extra_token and self.extra_token != self.credentials.token:
			return self.print_whoami_info(True)
	

	def get_user_groups(self):
		"""
		Get the groups of the current user.
		"""
		user_groups = []
		print(f"{Fore.YELLOW}Fetching groups of the current user...")

		try:
			page_size = 500
			view = "FULL"

			# Build the Cloud Resource Manager service
			crm_service = build('cloudresourcemanager', 'v1', http=self.authed_http())

			# Call the organizations.search method
			request = crm_service.organizations().search(body={})
			if self.billing_project:
				request.headers["X-Goog-User-Project"] = self.billing_project
			response = request.execute()

			organizations = response.get('organizations', [])
			if not organizations:
				print("No organizations found.")
				return None, None

			# Select the first organization
			if len(organizations) > 1:
				print(f"{Fore.YELLOW}Multiple organizations found {Fore.RESET}({', '.join([org['name'] for org in organizations])}). {Fore.GREEN}Using the first one.")
			
			org = organizations[0]
			org_id = org['name'].split('/')[-1]
			customer_id = org['owner']['directoryCustomerId']
			customer_id = f"customers/{customer_id}"

			service = build('cloudidentity', 'v1', http=self.authed_http())
			req = service.groups().list(pageSize=page_size, parent=customer_id, view=view)
			if self.billing_project:
				req.headers["X-Goog-User-Project"] = self.billing_project
			results = req.execute()
			groups = results.get('groups', [])

			for group in groups:
				group_name = group["name"]
				group_email = group["groupKey"]["id"]

				req2 = service.groups().memberships().searchTransitiveMemberships(
					parent=group_name,
					pageSize=page_size,
				)
				if self.billing_project:
					req2.headers["X-Goog-User-Project"] = self.billing_project
				results2 = req2.execute()

				memberships = results2.get('memberships', [])

				for membership in memberships:
					for keys in membership["preferredMemberKey"]:
						if keys["id"] == self.email:
							if group_email:
								user_groups.append(group_email)
							elif group_name:
								user_groups.append(group_name)

			return user_groups

		except Exception as e:
			print(f"{Fore.RED}Couldn't fetch groups of the current user. An error occurred: {e}")
			return []


	def list_drive_files(self, creds):
		"""
		List files from the Google Drive account associated with the current token.
		This requires the 'https://www.googleapis.com/auth/drive.readonly' scope.
		"""
		try:
			service = googleapiclient.discovery.build("drive", "v3", credentials=creds)
			page_token = None

			while True:
				results = service.files().list(
					pageSize=10,
					pageToken=page_token,
					fields="nextPageToken, files(id, name)"
				).execute()
				files = results.get('files', [])

				if not files:
					print(f"{Fore.YELLOW}No files found in Google Drive.")
					break

				for file in files:
					print(f"{Fore.BLUE}- {Fore.WHITE}{file['name']}")

				page_token = results.get('nextPageToken')
				if not page_token:
					print(f"{Fore.GREEN}No more files to display.")
					break

			if self.no_ask:
				cont = 'n'
			else:
				cont = input("Do you want to see more files? (y/N): ")


	def list_gmail_emails(self, creds):
		"""
		List emails from the Gmail account associated with the current token.
		This requires the 'https://www.googleapis.com/auth/gmail.readonly' scope.
		"""
		try:
			service = googleapiclient.discovery.build("gmail", "v1", credentials=creds)
			page_token = None

			while True:
				results = service.users().messages().list(
					userId='me',
					maxResults=10,
					pageToken=page_token
				).execute()
				messages = results.get('messages', [])

				if not messages:
					print(f"{Fore.YELLOW}No emails found.")
					break

				for message in messages:
					msg = service.users().messages().get(userId='me', id=message['id']).execute()
					headers = msg['payload'].get('headers', [])
					subject = next((header['value'] for header in headers if header['name'].lower() == 'subject'), "No Subject")
					from_email = next((header['value'] for header in headers if header['name'].lower() == 'from'), "Unknown Sender")
					print(f"{Fore.BLUE}Email Subject: {Fore.WHITE}{subject}")
					print(f"{Fore.BLUE}From Email: {Fore.WHITE}{from_email}")
					print(f"{Fore.BLUE}Snippet: {Fore.WHITE}{msg['snippet']}")
					print("-" * 50)

				page_token = results.get('nextPageToken')
				if not page_token:
					print(f"{Fore.GREEN}No more emails to display.")
					break

			if self.no_ask:
				cont = 'n'
			else:
				cont = input("Do you want to see more emails? (y/N): ")








if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="GCPPEASS: Enumerate GCP permissions and check for privilege escalations and other attacks with HackTricks AI.")

	scope_group = parser.add_mutually_exclusive_group(required=False)
	scope_group.add_argument('--projects', help="Known project IDs (project names) separated by commas")
	scope_group.add_argument('--folders', help="Known folder IDs (folder number) separated by commas")
	scope_group.add_argument('--organizations', help="Known organization IDs separated by commas")
	scope_group.add_argument('--service-accounts', help="Known service account emails separated by commas")

	auth_group = parser.add_mutually_exclusive_group(required=True)
	auth_group.add_argument('--sa-credentials-path', help="Path to credentials.json")
	auth_group.add_argument('--token', help="Raw access token")

	parser.add_argument('--extra-token', help="Extra token potentially with access over Gmail and/or Drive")
	parser.add_argument('--dont-get-iam-policies', action="store_true", default=False, help="Do not get IAM policies for the resources")
	parser.add_argument('--skip-bruteforce', action="store_true", default=False, help="Skip bruteforce permission enumeration without prompting")
	parser.add_argument('--no-ask', action="store_true", default=False, help="Do not ask for user input during execution, use defaults instead")
	parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/gcp_results.json)")
	parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
	parser.add_argument('--not-use-hacktricks-ai', action="store_true", default=False, help="Don't use Hacktricks AI to suggest attack paths")
	parser.add_argument('--billing-project', type=str, default="", help="Indicate the billing project to use to brute-force permissions")
	parser.add_argument('--proxy', type=str, default="", help="Indicate a proxy to use to connect to GCP for debugging (e.g. 127.0.0.1:8080)")
	parser.add_argument('--print-invalid-permissions', default=False, action="store_true", help="Print found invalid permissions to improve th speed of the tool")


	args = parser.parse_args()
	if args.token:
		token = os.getenv("CLOUDSDK_AUTH_ACCESS_TOKEN", args.token).rstrip()
	else:
		token = None
	
	sa_credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", args.sa_credentials_path)
	creds = google.oauth2.credentials.Credentials(token) if token else \
		google.oauth2.service_account.Credentials.from_service_account_file(
			sa_credentials_path, scopes=["https://www.googleapis.com/auth/cloud-platform"])

	gcp_peass = GCPPEASS(
		creds, args.extra_token, args.projects, args.folders, args.organizations,
		args.service_accounts,
		very_sensitive_combinations, sensitive_combinations,
		not_use_ht_ai=args.not_use_hacktricks_ai,
		num_threads=args.threads,
		out_path=args.out_json_path,
		billing_project=args.billing_project,
		proxy=args.proxy,
		print_invalid_perms=args.print_invalid_permissions,
		dont_get_iam_policies=args.dont_get_iam_policies,
		skip_bruteforce=args.skip_bruteforce,
		no_ask=args.no_ask
	)
	gcp_peass.run_analysis()
