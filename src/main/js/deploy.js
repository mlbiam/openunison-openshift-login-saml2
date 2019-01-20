//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

print("Loading CertUtils");
var CertUtils = Java.type("com.tremolosecurity.kubernetes.artifacts.util.CertUtils");

print("Creating openunison keystore");

ksPassword = inProp['unisonKeystorePassword'];
ouKs = Java.type("java.security.KeyStore").getInstance("PKCS12");
ouKs.load(null,ksPassword.toCharArray());

use_k8s_cm = true;


print("Generating openunison tls certificate");
certInfo = {
    "serverName":"openunison.openunison.svc.cluster.local",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

var x509data = CertUtils.createCertificate(certInfo);

if (use_k8s_cm) {
  print("Creating CSR for API server");



  csrReq = {
      "apiVersion": "certificates.k8s.io/v1beta1",
      "kind": "CertificateSigningRequest",
      "metadata": {
        "name": "openunison.openunison.svc.cluster.local",
      },
      "spec": {
        "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(x509data).getBytes("utf-8")),
        "usages": [
          "digital signature",
          "key encipherment",
          "server auth"
        ]
      }
    };

  print("Requesting certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(csrReq));

  print("Approving certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
      {
          "type":"Approved",
          "reason":"OpenUnison Deployment",
          "message":"This CSR was approved by the OpenUnison artifact deployment job"
      }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local','java.util.Base64.getDecoder().decode(JSON.parse(ws_response_json).status.certificate);check_ws_response=true;',10);
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;
  CertUtils.importSignedCert(x509data,b64cert);
}

print("Saving certificate to keystore");
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-tls",x509data);
CertUtils.createKey(ouKs,"session-unison",ksPassword);
CertUtils.createKey(ouKs,"lastmile-oidc",ksPassword);

print("Generating OIDC Certificate");

certInfo = {
    "serverName":"unison-saml2-rp-sig",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

x509data = CertUtils.createCertificate(certInfo);
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-saml2-rp-sig",x509data);

rp_sig_cert_bytes = x509data.getCertificate();

print("Storing k8s certs");
ouKs.setCertificateEntry('k8s-master',k8s.getCertificate('k8s-master'));


//import metadata

fXmlFile = new java.io.File("/etc/extracerts/saml2-metadata.xml");
dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
dBuilder = dbFactory.newDocumentBuilder();
doc = dBuilder.parse(fXmlFile);

//get entity id
entityId = doc.getElementsByTagName("EntityDescriptor").item(0).getAttribute("entityID");

idp = doc.getElementsByTagName("IDPSSODescriptor").item(0);

singleLogoutURL = "";
ssoGetURL = "";
ssoPostURL = "";
sig_certs = [];
sig_cert_to_use = ""

current_cert_choice = null;


//single logout
slos = idp.getElementsByTagName("SingleLogoutService");

for (i = 0;i<slos.getLength();i++) {
    slo = slos.item(i);
    if (slo.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        singleLogoutURL = slo.getAttribute("Location");
    }
}

//single sign on
ssos = idp.getElementsByTagName("SingleSignOnService");

for (i = 0;i<ssos.getLength();i++) {
    sso = ssos.item(i);
    if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        ssoGetURL = sso.getAttribute("Location");
    } else if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
        ssoPostURL = sso.getAttribute("Location");
    }
}

keys = idp.getElementsByTagName("KeyDescriptor");

for (i=0;i<keys.getLength();i++) {
    key = keys.item(i);

    if (key.getAttribute("use").equalsIgnoreCase("signing")) {
        sig_cert = key.getElementsByTagName("KeyInfo").item(0).getElementsByTagName("X509Data").item(0).getElementsByTagName("X509Certificate").item(0).getTextContent();
        sig_certs.push(sig_cert);
    }
}

if (sig_certs.length == 1) {
    current_cert_choice = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[0]);
} else {
    for (i=0;i<sig_certs.length;i++) {
        current_cert = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[i]);
        if (current_cert_choice == null) {
            current_cert_choice = current_cert;
        } else {
            if (current_cert_choice.getNotAfter().compareTo(current_cert.getNotAfter())  < 0  ) {
                current_cert_choice = current_cert;
            }
        }
    }
    
}


inProp['IDP_ENTITY_ID'] = entityId;
inProp['IDP_POST'] = ssoPostURL;
inProp['IDP_REDIR'] = ssoGetURL;
inProp['IDP_LOGOUT'] = singleLogoutURL;


ouKs.setCertificateEntry('idp-saml2-sig',current_cert_choice);


print("Create the openunison namespace");

ouNS = {
    "apiVersion":"v1",
    "kind":"Namespace",
    "metadata":{
        "creationTimestamp":null,
        "name":"openunison"
    },
    "spec":{},
    "status":{}
};

k8s.postWS('/api/v1/namespaces',JSON.stringify(ouNS));

if (inProp['REG_CRED_USER'] != null) {
  username = inProp['REG_CRED_USER'];
  password = inProp['REG_CRED_PASSWORD'];
  b64Creds = java.util.Base64.getEncoder().encodeToString((username + ':' + password).getBytes("UTF-8"));
  //TODO determine this from the builder image
  credServer = inProp['BUILDER_IMAGE'].substring(0,inProp['BUILDER_IMAGE'].indexOf('/'));
  print("Registry Server - '" + credServer + "'");


  docker_creds = {};
  docker_creds["auths"] = {};
  docker_creds["auths"][credServer] = {
    "username": username,
    "password": password,
    "email": "doesnotmatter@doesnotmatter.com",
    "auth": b64Creds
  };

  
  docker_secret = {
    "apiVersion": "v1",
    "data": {
      ".dockerconfigjson": java.util.Base64.getEncoder().encodeToString(JSON.stringify(docker_creds).getBytes("UTF-8"))
    },
    "kind": "Secret",
    "metadata": {
      "name": "redhat-registry",
      "namespace":"openunison"
    },
    "type": "kubernetes.io/dockerconfigjson"
  }

  res = k8s.postWS("/api/v1/namespaces/openunison/secrets",JSON.stringify(docker_secret));
  print(res.data);

}


print("import builder image");


import_builder_image = {
  "kind": "ImageStreamImport",
  "apiVersion": "image.openshift.io/v1",
  "metadata": {
    "name": "openunison-s2i",
    "namespace": "openunison",
    "creationTimestamp": null
  },
  "spec": {
    "import": true,
    "images": [
      {
        "from": {
          "kind": "DockerImage",
          "name": inProp['BUILDER_IMAGE']
        },
        "to": {
          "name": "latest"
        },
        "importPolicy": {},
        "referencePolicy": {
          "type": ""
        }
      }
    ]
  },
  "status": {}
};

res = k8s.postWS("/apis/image.openshift.io/v1/namespaces/openunison/imagestreamimports",JSON.stringify(import_builder_image));
print(res.data);


print("Create openunison service account");

k8s.postWS('/api/v1/namespaces/openunison/serviceaccounts',JSON.stringify({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"creationTimestamp":null,"name":"openunison"}}));


print("Creating RBAC Bindings");

rbac = {
	"kind": "ClusterRole",
	"apiVersion": "rbac.authorization.k8s.io/v1",
	"metadata": {
		"name": "cluster-admin-access"
	},
	"rules": [
		{
			"apiGroups": [
				""
			],
			"resources": [
				"groups",
				"users"
			],
			"verbs": [
				"get",
				"list",
				"watch",
				"create",
				"update",
				"patch",
				"delete"
			]
		}
	]
};

k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterroles",JSON.stringify(rbac));

rbac = {
    "kind": "ClusterRoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "openunison-user-provisioner"
    },
    "subjects": [
      {
        "kind": "ServiceAccount",
        "name": "openunison",
        "namespace": "openunison"
      }
    ],
    "roleRef": {
      "kind": "ClusterRole",
      "name": "cluster-admin-access",
      "apiGroup": "rbac.authorization.k8s.io"
    }
  };

k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",JSON.stringify(rbac));

rbac = {
    "kind": "ClusterRole",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "list-namespaces"
    },
    "rules": [
      {
        "apiGroups": [
          ""
        ],
        "resources": [
          "namespaces"
        ],
        "verbs": [
          "list"
        ]
      }
    ]
  };

k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterroles",JSON.stringify(rbac));

rbac = {
    "kind": "ClusterRoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {
      "name": "openunison-cluster-list-namespaces"
    },
    "subjects": [
      {
        "kind": "Group",
        "name": "users",
        "apiGroup": "rbac.authorization.k8s.io"
      }
    ],
    "roleRef": {
      "kind": "ClusterRole",
      "name": "list-namespaces",
      "apiGroup": "rbac.authorization.k8s.io"
    }
  };


k8s.postWS("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",JSON.stringify(rbac));


print("Create OpenUnison Secret");


ouSecrets = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"openunison-secrets",
        "namespace":"openunison"
    },
    "data":{
      "openunison.yaml":"LS0tCm9wZW5fcG9ydDogODA4MApvcGVuX2V4dGVybmFsX3BvcnQ6IDgwCnNlY3VyZV9wb3J0OiA4NDQzCnNlY3VyZV9leHRlcm5hbF9wb3J0OiA0NDMKc2VjdXJlX2tleV9hbGlhczogInVuaXNvbi10bHMiCmZvcmNlX3RvX3NlY3VyZTogdHJ1ZQphY3RpdmVtcV9kaXI6ICIvdG1wL2FtcSIKcXVhcnR6X2RpcjogIi90bXAvcXVhcnR6IgpjbGllbnRfYXV0aDogbm9uZQphbGxvd2VkX2NsaWVudF9uYW1lczogW10KY2lwaGVyczoKLSBUTFNfUlNBX1dJVEhfUkM0XzEyOF9TSEEKLSBUTFNfUlNBX1dJVEhfQUVTXzEyOF9DQkNfU0hBCi0gVExTX1JTQV9XSVRIX0FFU18yNTZfQ0JDX1NIQQotIFRMU19SU0FfV0lUSF8zREVTX0VERV9DQkNfU0hBCi0gVExTX1JTQV9XSVRIX0FFU18xMjhfQ0JDX1NIQTI1NgotIFRMU19SU0FfV0lUSF9BRVNfMjU2X0NCQ19TSEEyNTYKcGF0aF90b19kZXBsb3ltZW50OiAiL3Vzci9sb2NhbC9vcGVudW5pc29uL3dvcmsiCnBhdGhfdG9fZW52X2ZpbGU6ICIvZXRjL29wZW51bmlzb24vb3UuZW52IgoK",
      "ou.env":k8s.encodeMap(inProp),
      "unisonKeyStore.p12":CertUtils.encodeKeyStore(ouKs,ksPassword)
    }
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ouSecrets));

print("Creating post deployment configmap");

print("Runing kubectl create");
k8s.kubectlCreate(k8s.processTemplate(deploymentTemplate,inProp));
print("kubectl complete");



ou_route = {
	"kind": "Route",
	"apiVersion": "route.openshift.io/v1",
	"id": "openunison-https",
	"metadata": {
		"name": "secure-openunison",
		"labels": {
			"application": "openunison"
		},
		"annotations": {
			"description": "Route for OpenUnison's https service."
		}
	},
	"spec": {
		"host": inProp['OU_HOST'],
		"port": {
			"targetPort": "secure"
		},
		"to": {
			"kind": "Service",
			"name": "secure-openunison"
		},
		"tls": {
			"termination": "reencrypt",
      "destinationCACertificate":CertUtils.exportCert(k8s.getCertificate('k8s-master'))
		}
	}
};

k8s.postWS('/apis/route.openshift.io/v1/namespaces/openunison/routes',JSON.stringify(ou_route));

ou_imagestream = {
	"kind": "ImageStream",
	"apiVersion": "image.openshift.io/v1",
	"metadata": {
		"name": "openunison",
		"labels": {
			"application": "openunison"
		}
	}
};

k8s.postWS('/apis/image.openshift.io/v1/namespaces/openunison/imagestreams',JSON.stringify(ou_imagestream));

ou_build = {
	"kind": "BuildConfig",
	"apiVersion": "build.openshift.io/v1",
	"metadata": {
		"name": "openunison",
		"labels": {
			"application": "openunison"
		}
	},
	"spec": {
		"source": {
			"type": "Git",
			"git": {
				"uri": "https://github.com/OpenUnison/openunison-openshift-login-saml2.git",
				"ref": "master"
			},
			"contextDir": "/"
		},
		"strategy": {
			"type": "Source",
			"sourceStrategy": {
				"env": [],
				"forcePull": true,
				"from": {
					"kind": "ImageStreamTag",
					"namespace": "openunison",
					"name": "openunison-s2i:latest"
				}
			}
		},
		"output": {
			"to": {
				"kind": "ImageStreamTag",
				"name": "openunison:latest"
			}
		},
		"triggers": [
			{
				"type": "ImageChange",
				"imageChange": {}
			},
			{
				"type": "ConfigChange"
			}
		]
	}
};

if (inProp['REG_CRED_USER'] != null) {
  ou_build.spec.strategy.sourceStrategy['pullSecret'] = {"name":"redhat-registry"};
}

k8s.postWS('/apis/build.openshift.io/v1/namespaces/openunison/buildconfigs',JSON.stringify(ou_build));

ou_deployment = {
	"kind": "DeploymentConfig",
	"apiVersion": "apps.openshift.io/v1",
	"metadata": {
		"name": "openunison",
		"labels": {
			"application": "openunison"
		}
	},
	"spec": {
		"strategy": {
			"type": "Recreate"
		},
		"triggers": [
			{
				"type": "ImageChange",
				"imageChangeParams": {
					"automatic": true,
					"containerNames": [
						"openunison"
					],
					"from": {
						"kind": "ImageStreamTag",
						"name": "openunison:latest"
					}
				}
			},
			{
				"type": "ConfigChange"
			}
		],
		"replicas": 1,
		"selector": {
			"deploymentConfig": "openunison"
		},
		"template": {
			"metadata": {
				"name": "openunison",
				"labels": {
					"deploymentConfig": "openunison",
					"application": "openunison"
				}
			},
			"spec": {
				"terminationGracePeriodSeconds": 60,
				"containers": [
					{
						"name": "openunison",
						"image": "openunison",
						"imagePullPolicy": "Always",
						"volumeMounts": [
							{
								"name": "secret-volume",
								"mountPath": "/etc/openunison",
								"readOnly": true
							}
						],
						"livenessProbe": {
							"exec": {
								"command": [
									"/usr/local/openunison/bin/check_alive.py"
								]
							},
							"initialDelaySeconds": 30,
							"timeoutSeconds": 10,
              "failureThreshold":10
						},
						"readinessProbe": {
							"exec": {
								"command": [
									"/usr/local/openunison/bin/check_alive.py"
								]
							},
							"initialDelaySeconds": 30,
							"timeoutSeconds": 10,
              "failureThreshold":10
						},
						"ports": [
							{
								"name": "http",
								"containerPort": 8080,
								"protocol": "TCP"
							},
							{
								"name": "https",
								"containerPort": 8443,
								"protocol": "TCP"
							}
						],
						"env": [
							{
								"name": "JAVA_OPTS",
								"value": "-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom\n-DunisonEnvironmentFile=/etc/openunison/ou.env"
							}
						]
					}
        ],
        "serviceAccount":"openunison",
        "serviceAccountName":"openunison",
				"volumes": [
					{
						"name": "secret-volume",
						"secret": {
							"secretName": "openunison-secrets"
						}
					}
				]
			}
		}
	}
};

k8s.postWS('/apis/apps.openshift.io/v1/namespaces/openunison/deploymentconfigs',JSON.stringify(ou_deployment));



xmlMetaData =  '<EntityDescriptor ID="_10685acd-7df4-427e-b61e-68e4f6407c24" entityID="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n';
xmlMetaData += '  <SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n';
xmlMetaData += '      <KeyDescriptor use="signing">\n';
xmlMetaData += '        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n';
xmlMetaData += '              <X509Data>\n';
xmlMetaData += '                  <X509Certificate>\n' + new org.apache.commons.codec.binary.Base64(64).encodeToString(rp_sig_cert_bytes.getEncoded()) + '</X509Certificate>\n';
xmlMetaData += '              </X509Data>\n';
xmlMetaData += '          </KeyInfo>\n';
xmlMetaData += '      </KeyDescriptor>\n';
xmlMetaData += '      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth"/>\n';
xmlMetaData += '      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="0" isDefault="true"/>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="1"/>\n';
xmlMetaData += '  </SPSSODescriptor>\n';
xmlMetaData += '</EntityDescriptor>';


post_deploy_instructions = "After the build is complete:\n" +
                           " 1.  In the same directory as your ansible inventory file, create a file called group_vars/OSEv3.yaml\n" +
                           " 2.  Add the following YAML to this file:\n" +
                           "openshift_master_identity_providers:\n" +
                           "- name: openunison\n" +
                           "  challenge: false\n" +
                           "  login: true\n" +
                           "  mappingMethod: claim\n" +
                           "  kind: OpenIDIdentityProvider\n" +
                           "  clientID: openshift\n" +
                           "  clientSecret: YOUR_SECRET\n" +
                           "  ca: /etc/origin/master/openunison_openid_ca.crt\n" +
                           "  claims:\n" +
                           "    id:\n" +
                           "    - sub\n" +
                           "    preferredUsername:\n" +
                           "    - preferred_username\n" + 
                           "    name:\n" +
                           "    - name\n" +
                           "    email:\n" +
                           "    - email\n" +
                           "  urls:\n" +
                           "    authorize: https://" + inProp["OU_HOST"] + "/auth/idp/OpenShiftIdP/auth\n" +
                           "    token: https://" + inProp["OU_HOST"] + "/auth/idp/OpenShiftIdP/token\n" +
                           "3.  In your inventory, set openshift_master_logout_url=https://" + inProp['OU_HOST'] + "/logout\n" +
                           "4.  Step 3 will NOT update the ConfigMap that controls this setting, so follow the instructions at https://docs.openshift.com/container-platform/3.11/install_config/web_console_customization.html#changing-the-logout-url\n" +
                           "5.  If you're router is using the default wildcard certificate generated by OpenShift, copy /etc/origin/master/ca.crt to /etc/origin/master/openunison_openid_ca.crt.  If using a 3rd party CA issued certificate, make sure to copy it to /etc/origin/master/openunison_openid_ca.crt on each master. \n" +
                           "6.  Run the openshift-ansible/playbooks/openshift-master/config.yml playbook\n" + 
                           "7.  Import the metadata generated in saml2-rp-metadata" 
                           



cfgMap = {
    "apiVersion":"v1",
    "kind":"ConfigMap",
    "metadata":{
        "name":"api-server-config",
        "namespace":"openunison"
    },
    "data":{
        "post-deploy-instructions":post_deploy_instructions,
        "openshift_idp_configuration":"",
        "saml2-rp-metadata":xmlMetaData
        
        //"deployment":java.util.Base64.getEncoder().encodeToString(k8s.processTemplate(deploymentTemplate,inProp).getBytes("UTF-8"))
    }
};

k8s.postWS('/api/v1/namespaces/openunison/configmaps',JSON.stringify(cfgMap));

print("Deleting cluster role binding");
k8s.deleteWS('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/artifact-deployment');

print("Artifacts Created, to configure the API server run 'kubectl describe configmap api-server-config -n openunison'");