import argparse
import requests
import google.oauth2.credentials
import googleapiclient.discovery
import httplib2
import re
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from tqdm import tqdm
from colorama import Fore, Style, init, Back
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp

from src.CloudPEASS.cloudpeass import CloudPEASS
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



INVALID_PERMS = {}


class GCPPEASS(CloudPEASS):
	def __init__(self, credentials, extra_token, project, folder, org, very_sensitive_combos, sensitive_combos, not_use_ht_ai, num_threads, out_path, billing_project, proxy, print_invalid_perms, dont_get_iam_policies):
		self.credentials = credentials
		self.extra_token = extra_token
		self.project = project
		self.folder = folder
		self.org = org
		self.billing_project = billing_project
		self.email = ""
		self.is_sa = False
		self.groups = []
		self.print_invalid_perms = print_invalid_perms
		self.dont_get_iam_policies = dont_get_iam_policies
		
		if proxy:
			proxy = proxy.split("//")[-1] # Porotocol not needed
			self.proxy_host = proxy.split(":")[0]
			self.proxy_port = int(proxy.split(":")[1])
		else:
			self.proxy_host = None
			self.proxy_port = None
		
		self.all_gcp_perms = self.download_gcp_permissions()

		super().__init__(very_sensitive_combos, sensitive_combos, "GCP", not_use_ht_ai, num_threads,
						 GCP_MALICIOUS_RESPONSE_EXAMPLE, GCP_SENSITIVE_RESPONSE_EXAMPLE, out_path)

	def download_gcp_permissions(self):
		base_ref_page = requests.get("https://cloud.google.com/iam/docs/permissions-reference").text
		permissions = re.findall('<td id="([^"]+)"', base_ref_page)
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

		if self.project: # It's important that  project is the first thing to check
			targets.append({"id": f"projects/{self.project}", "type": "project"})
		if self.folder:
			targets.append({"id": f"folders/{self.folder}", "type": "folder"})
		if self.org:
			targets.append({"id": f"organizations/{self.org}", "type": "organization"})

		for proj in self.list_projects():
			targets.append({"id": f"projects/{proj}", "type": "project"})
		for folder in self.list_folders():
			targets.append({"id": f"folders/{folder}", "type": "folder"})
		for org in self.list_organizations():
			targets.append({"id": f"organizations/{org}", "type": "organization"})

		### For each project, add VMs, Cloud Functions, and Storage buckets ###
		print("Trying to list VMs, Cloud Functions, Storage buckets and Service Accounts on each project...")
		def process_project(proj):
			local_targets = []
			for vm in self.list_vms(proj):
				local_targets.append({"id": vm, "type": "vm"})
			for func in self.list_functions(proj):
				local_targets.append({"id": func, "type": "function"})
			for bucket in self.list_storages(proj):
				local_targets.append({"id": bucket, "type": "storage"})
			for sa in self.list_service_accounts(proj):
				local_targets.append({"id": sa, "type": "service_account"})
			return local_targets

		# Process projects concurrently using a thread pool
		with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
			futures = {executor.submit(process_project, proj): proj for proj in self.list_projects()}
			for future in tqdm(as_completed(futures), total=len(futures), desc="Processing projects"):
				targets.extend(future.result())
				





		### Start looking for IAM policies and permissions ###
		found_permissions = []
		lock = Lock()

		def process_target_iam(target):
			# Attempt to retrieve IAM policy
			policy = self.get_iam_policy(target["id"])
			collected = []

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
						
						elif "goup:" in member and self.groups:
							if any(g.lower() in member.lower() for g in self.groups):
								affected = True
						
						elif member.startswith("organizations/") and not self.is_sa:
								affected = True

						if affected:
							role = binding.get("role")
							permissions = self.get_permissions_from_role(role)
							collected.extend(permissions)
			
			return {
				"id": target["id"],
				"name": target["id"].split("/")[-1] if len(target["id"].split("/")) > 2 else target["id"],
				"permissions": collected,
				"type": target["type"]
			}
		
		if not self.dont_get_iam_policies:
			# Use a thread pool to process each target concurrently
			with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
				# Submit tasks for each target
				futures = {executor.submit(process_target_iam, target): target for target in targets}
				# Iterate over completed futures with a progress bar
				for future in tqdm(as_completed(futures), total=len(futures), desc="Checking IAM policies", leave=False):
					res = future.result()
					with lock:
						found_permissions.append(res)

		


		### Start bruteforcing permissions ###

		# Function to process each target resource
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
				for future in tqdm(as_completed(futures), total=len(futures), desc=f"Checking permissions for {target['id']}", leave=False):
					result = future.result()
					collected.extend(result)

			return {
				"id": target["id"],
				"name": target["id"].split("/")[-1] if len(target["id"].split("/")) > 2 else target["id"],
				"permissions": collected,
				"type": target["type"]
			}

		if not targets:
			print(f"{Fore.RED}No targets found! Indicate a project, folder or organization manually. Exiting.")
			exit(1)

		
		# Check if the user has permissions to check the permissions
		relevant_perms = self.get_relevant_permissions(targets[0]["type"])
		perms_chunks = [relevant_perms[i:i+20] for i in range(0, len(relevant_perms), 20)]
		# Just pass some permissions to check if the API is enabled
		can_bf_permissions = self.can_check_permissions(targets[0]["id"], perms_chunks[0])				
		if can_bf_permissions:
			with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
				futures = {executor.submit(process_target, target): target for target in targets}
				for future in tqdm(as_completed(futures), total=len(futures)):
					res = future.result()
					with lock:
						found_permissions.append(res)

		if self.print_invalid_perms and INVALID_PERMS:
			print(f"{Fore.YELLOW}Invalid permissions found:")
			for resource, perms in INVALID_PERMS.items():
				print(f"{Fore.BLUE}{resource}: {', '.join(perms)}")

		return found_permissions
	





















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
					msg += f"\n{Fore.BLUE}User groups: {Fore.WHITE}{', '.join(self.groups)}"

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
			user_input = input(f"{Fore.YELLOW}Do you want to list emails? [Y/n]: {Fore.WHITE}")
			if user_input.lower() != 'n':
				self.list_gmail_emails(google.oauth2.credentials.Credentials(token))
		
		if any("/drive" in s for s in scopes):
			print(f"{Fore.GREEN}Note: You have Drive API access.")
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
							user_groups.append(group_email)

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

				cont = input("Do you want to see more files? (y/N): ")
				if cont.lower() != 'y':
					break

		except Exception as e:
			print(f"{Fore.RED}Error listing files: {e}")


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

				cont = input("Do you want to see more emails? (y/N): ")
				if cont.lower() != 'y':
					break

		except Exception as e:
			print(f"{Fore.RED}Error listing emails: {e}")








if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="GCPPEASS: Enumerate GCP permissions and check for privilege escalations and other attacks with HackTricks AI.")

	scope_group = parser.add_mutually_exclusive_group(required=False)
	scope_group.add_argument('--project', help="Project ID (project name)")
	scope_group.add_argument('--folder', help="Folder ID (folder number)")
	scope_group.add_argument('--organization', help="Organization ID")

	auth_group = parser.add_mutually_exclusive_group(required=True)
	auth_group.add_argument('--sa-credentials-path', help="Path to credentials.json")
	auth_group.add_argument('--token', help="Raw access token")

	parser.add_argument('--extra-token', help="Extra token potentially with access over Gmail and/or Drive")
	parser.add_argument('--dont-get-iam-policies', action="store_true", default=False, help="Do not get IAM policies for the resources")
	parser.add_argument('--out-json-path', default=None, help="Output JSON file path (e.g. /tmp/gcp_results.json)")
	parser.add_argument('--threads', default=5, type=int, help="Number of threads to use")
	parser.add_argument('--not-use-hacktricks-ai', action="store_false", default=False, help="Don't use Hacktricks AI to analyze permissions")
	parser.add_argument('--billing-project', type=str, default="", help="Indicate the billing project to use to brute-force permissions")
	parser.add_argument('--proxy', type=str, default="", help="Indicate a proxy to use to connect to GCP for debugging (e.g. 127.0.0.1:8080)")
	parser.add_argument('--print-invalid-permissions', default=False, action="store_true", help="Print found invalid permissions to improve th speed of the tool")


	args = parser.parse_args()
	if args.token:
		token = os.getenv("CLOUDSDK_AUTH_ACCESS_TOKEN", args.token).rstrip()
	else:
		token = None
	
	if args.folder: # Check all numbers
		if not args.folder.isdigit():
			print(f"{Fore.RED}Folder ID must be a number.")
			exit(1)
	
	if args.organization: # Check all numbers
		if not args.organization.isdigit():
			print(f"{Fore.RED}Organization ID must be a number.")
			exit(1)
		
	sa_credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", args.sa_credentials_path)
	creds = google.oauth2.credentials.Credentials(token) if token else \
		google.oauth2.service_account.Credentials.from_service_account_file(
			sa_credentials_path, scopes=["https://www.googleapis.com/auth/cloud-platform"])

	gcp_peass = GCPPEASS(
		creds, args.extra_token, args.project, args.folder, args.organization,
		very_sensitive_combinations, sensitive_combinations,
		not_use_ht_ai=args.not_use_hacktricks_ai,
		num_threads=args.threads,
		out_path=args.out_json_path,
		billing_project=args.billing_project,
		proxy=args.proxy,
		print_invalid_perms=args.print_invalid_permissions,
		dont_get_iam_policies=args.dont_get_iam_policies
	)
	gcp_peass.run_analysis()