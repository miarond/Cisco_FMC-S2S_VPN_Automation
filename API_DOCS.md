# Site to Site VPN Automation in FMC

The process of creating Site to Site VPNs in a Firepower Management Controller (FMC) can be automated through the use of FMC's REST API interface.  This document will explain how to accomplish that through step-by-step procedures, and the included Python script will demonstrate that capability.

## Table of Contents

* [Procedural Workflow](#procedural-workflow)
* [Procedure](#procedure)
  * [Authenticate to the FMC](#authenticate-to-the-fmc)
  * [Get IKE Policies](#get-ike-policies)
  * [Get Network Objects](#get-network-objects)
  * [Get Device Details](#get-device-details)
  * [Get Device Interface Details](#get-device-interface-details)
  * [Create Site to Site VPN Policy](#create-site-to-site-vpn-policy)
  * [Update IKE Settings on Site to Site VPN Policy](#update-ike-settings-on-site-to-site-vpn-policy)
  * [Configure Node A Endpoint (FTD Device)](#configure-endpoint-node-a-ftd-device)
  * [Configure Node B Endpoint (Remote Device)](#configure-endpoint-node-b-remote-device)
  * [Get Site to Site VPN Policy Config](#get-site-to-site-vpn-policy-config)

---

### Procedural Workflow

Below is a diagram that depicts the workflow process for creating a Site to Site VPN in FMC, and all of the related objects and steps that are involved.

![Workflow Diagram](/assets/workflow_diagram.png)

[Return to ToC](#table-of-contents)

---

## Procedure

The FMC product maintains an internal database of "objects" for everything that it manages and creates.  Each of these objects is stored as a separate record and an ID, called a Universally Unique Identifier (UUID), is generated for each one.  When two or more objects need to be related in some way - for instance, a Site to Site VPN Policy needs to be related to an existing IKEv1 or IKEv2 Policy object - they are referenced by their UUID.  As a result, many separate API calls must be made to the FMC to gather these UUIDs because administrators will normally only know the friendly name of the object.  We must match those names to their UUID so that we can build the necessary object relationships, in order to create a new Policy object.

The following section will detail the process of creating a Site to Site VPN Policy in FMC, all of the API calls necessary, and examples of what the JSON payloads should look like for any `POST` or `PUT` API calls.

[Return to ToC](#table-of-contents)

---

### Authenticate to the FMC

***Request:***

**URI:** `https://<fmc_server>/api/fmc_platform/v1/auth/generatetoken` </br>
**Method:** `POST` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "Authorization": "Basic <base64_enStatus Coded_string>"
}
```
  > *Note: This API uses the Basic HTTP authentication method.  The <base64_encoded_string> in the Authorization header is created by generating the Base64 encoding of the string `username:password`.  For example, the Base64 encoding of `admin:password` would be `YWRtaW46cGFzc3dvcmQ=`.*

***Response:***

**Status Code:** `200`, `204` </br>
**Headers:**
```json
{
  ...<truncated>,
  "X-auth-access-token": "<jwt_token>",
  "X-auth-refresh-token": "<jwt_token>",
  "DOMAIN_UUID": "<domain_uuid>",
  ...<truncated>
}
```
**Payload:** None
  > *Note: The authentication token, a refresh token, and the Domain UUID are among the header values returned by the FMC.  You will need the `X-auth-access-token` and `DOMAIN_UUID` for all subsequent API calls.*

[Return to ToC](#table-of-contents)

---

### Get IKE Policies

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/object/ikev1policies` </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/object/ikev2policies` </br>
**Method:** `GET` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
```

***Response:***

**Status Code:** `200` </br>
**Headers:** N/A </br>
**Payload:**
```json
[
  "links": {
    "self": "<ref_link>"
  },
  "items": [
    {
      "links": {
        "self": "<ref_link>"
      },
      "type": "IKEv2Policy",
      "name": "AES-GCM-NULL-SHA",
      "id": "00505697-B8D7-0ed3-0000-000000000400"
    },
    ...<truncated>
  ],
  "paging": {
    "offset": 0,
    "limit": 7,
    "count": 7,
    "pages": 1
  }
]
```

[Return to ToC](#table-of-contents)

---

### Get Network Objects

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/object/networks` </br>
**Method:** `GET` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
```

***Response:***

**Status Code:** `200` </br>
**Headers:** N/A </br>
**Payload:**
```json
[
  "links": {
    "self": "<ref_link>"
  },
  "items": [
    {
      "links": {
        "self": "<ref_link>",
        "parent": "<ref_link>"
      },
      "type": "Network",
      "id": "00505697-B8D7-0ed3-0000-111669151524",
      "name": "10.10.10.0_24"
    },
    ...<truncated>
  ],
  "paging": {
    "offset": 0,
    "limit": 25,
    "count": 14,
    "pages": 1
  }
]
```

[Return to ToC](#table-of-contents)

---

### Get Device Details

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/devices/devicerecords` </br>
**Method:** `GET` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
```
**Query Parameters:**
```json
{
  "filter": "name:<fmc_inventory_device_name>"
}
```
*OR*
```json
{
  "filter": "hostName:<ftd_hostname>"
}
```
  > *Note: Optionally, you can specify the Query Parameter `"expanded": true` to have full details returned.  Query Parameters are appended to the end of the API URI string in the format: `https://<uri_string>?param_1=value_1&param_2=value_2`*

***Response:***

**Status Code:** `200` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "links": {
    "self": "<ref_link>"
  },
  "items": [
    {
      "id": "289140c4-2369-11ea-938e-91f922b309a7",
      "type": "Device",
      "links": {
        "self": "<ref_link>"
      },
      "name": "FTD"
    }
  ],
  "paging": {
    "offset": 0,
    "limit": 25,
    "count": 1,
    "pages": 1
  }
}
```

[Return to ToC](#table-of-contents)

---

### Get Device Interface Details

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/devices/devicerecords/<device_uuid>/ftdallinterfaces` </br>
**Method:** `GET` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
```
**Query Parameters:**
```json
{
  "expanded": true
}
```
  > *Note: Query Parameters are appended to the end of the API URI string in the format: `https://<uri_string>?param_1=value_1&param_2=value_2`*

***Response:***

**Status Code:** `200` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "links": {
    "self": "<ref_link>"
  },
  "items": [
    {
      "links": {
        "self": "<ref_link>"
      },
      "type": "PhysicalInterface",
      "enabled": true,
      "MTU": 1500,
      "name": "GigabitEthernet0/0",
      "priority": 0,
      "id": "00505697-B8D7-0ed3-0000-111669149808",
      "mode": "NONE",
      "enableSGTPropagate": false,
      "ipv6": {
        "enableRA": true,
        "enableIPV6": false,
        "enforceEUI64": false,
        "enableAutoConfig": false,
        "enableDHCPAddrConfig": false,
        "enableDHCPNonAddrConfig": false,
        "dadAttempts": 1,
        "nsInterval": 1000,
        "reachableTime": 0,
        "raLifeTime": 1800,
        "raInterval": 200
      },
      "managementOnly": false,
      "securityZone": {
        "id": "0612e35c-2aec-11ee-8441-abae32bd8824",
        "type": "SecurityZone"
      },
      "ifname": "Inside_Interface",
      "ipv4": {
        "static": {
          "address": "10.10.10.1",
          "netmask": "24"
        }
      },
      "enableAntiSpoofing": false,
      "fragmentReassembly": false
    },
    ...<truncated>
  ],
  "paging": {
    "offset": 0,
    "limit": 25,
    "count": 5,
    "pages": 1
  }
}
```

[Return to ToC](#table-of-contents)

---

### Create Site to Site VPN Policy

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/policy/ftds2svpns` </br>
**Method:** `POST` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
``` 

**Payload:** </br>
*Using IKEv1:*
```json
{
  "name": <policy_name>,
  "type": "FTDS2SVpn",
  "topologyType": "POINT_TO_POINT",
  "ikeV1Enabled": true,
  "ikeV2Enabled": false
}
```

*Using IKEv2:*
```json
{
  "name": <policy_name>,
  "type": "FTDS2SVpn",
  "topologyType": "POINT_TO_POINT",
  "ikeV1Enabled": false,
  "ikeV2Enabled": true
}
```

***Response:***

**Status Code:** `201` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "name": "Test_Policy_1",
  "id": "00505697-B8D7-0ed3-0000-111669150196",
  "type": "FTDS2SVpn",
  "links": {
    "self": "<ref_link>"
  },
  "ipsecSettings": {
    "tfcPackets": {
      "enabled": false,
      "burstBytes": 0,
      "payloadBytes": 0,
      "timeoutSeconds": 0
    },
    "cryptoMapType": "STATIC",
    "perfectForwardSecrecy": {
      "enabled": false
    },
    "ikeV2Mode": "TUNNEL",
    "enableSaStrengthEnforcement": false,
    "enableRRI": true,
    "lifetimeSeconds": 28800,
    "lifetimeKilobytes": 4608000,
    "validateIncomingIcmpErrorMessage": false,
    "doNotFragmentPolicy": "NONE",
    "id": "005056A9-7483-0ed3-0000-012884902863",
    "type": "IPSecSetting",
    "links": {
      "self": "<ref_link>"
    },
    "ikeV2IpsecProposal": [
      {
        "name": "AES-GCM",
        "id": "00505697-B8D7-0ed3-0000-000000002010",
        "type": "IKEv2IPsecProposal"
      }
    ]
  },
  "endpoints": {
    "refType": "list",
    "type": "EndPoint",
    "links": {
      "self": "<ref_link>"
    }
  },
  "ikeSettings": {
    "links": {
      "self": "<ref_link>"
    },
    "id": "005056A9-7483-0ed3-0000-012884902862",
    "type": "IkeSetting"
  },
  "advancedSettings": {
    "id": "005056A9-7483-0ed3-0000-012884902864",
    "type": "AdvancedSetting",
    "links": {
      "self": "<ref_link>"
    },
    "advancedTunnelSetting": {
      "certificateMapSettings": {
        "useCertMapConfiguredInEndpointToDetermineTunnel": false,
        "useCertificateOuToDetermineTunnel": true,
        "useIkeIdentityOuToDetermineTunnel": true,
        "usePeerIpAddressToDetermineTunnel": true
      },
      "enableSpokeToSpokeConnectivityThroughHub": false,
      "natKeepaliveMessageTraversal": {
        "enabled": true,
        "intervalSeconds": 20
      },
      "bypassAccessControlTrafficForDecryptedTraffic": false
    },
    "advancedIpsecSetting": {
      "maximumTransmissionUnitAging": {
        "enabled": false
      },
      "enableFragmentationBeforeEncryption": true
    },
    "advancedIkeSetting": {
      "ikeKeepaliveSettings": {
        "ikeKeepalive": "ENABLED",
        "threshold": 10,
        "retryInterval": 2
      },
      "enableAggressiveMode": false,
      "cookieChallenge": "CUSTOM",
      "identitySentToPeer": "AUTO_OR_DN",
      "enableNotificationOnTunnelDisconnect": false,
      "thresholdToChallengeIncomingCookies": 50,
      "percentageOfSAsAllowedInNegotiation": 100,
      "peerIdentityValidation": "REQUIRED"
    }
  },
  "routeBased": false,
  "topologyType": "POINT_TO_POINT",
  "ikeV1Enabled": false,
  "ikeV2Enabled": true
}
```

[Return to ToC](#table-of-contents)

---

### Update IKE Settings on Site to Site VPN Policy

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/policy/ftds2svpns/<s2s_vpn_policy_uuid>/ikesettings/<ike_settings_uuid>` </br>
**Method:** `POST` </br>
**Headers:**
```json
{
  "Content-Type": "application/json",
  "X-auth-access-token": "<token>"
}
``` 

**Payload:** </br>
*IKEv1 example using pre-shared key:*
```json
{
  "ikeV1Settings": {
      "authenticationType": "MANUAL_PRE_SHARED_KEY",
      "manualPreSharedKey": <psk_value>,
      "policies": [
          {
              "name": <ike_policy_name>,
              "id": <ike_policy_uuid>,
              "type": "IKEv1Policy"
          }
      ]
  },
  "id": "",
  "type": "IkeSetting"
}
```

*IKEv2 example using pre-shared key:*
```json
{
  "ikeV2Settings": {
      "authenticationType": "MANUAL_PRE_SHARED_KEY",
      "enforceHexBasedPreSharedKeyOnly": false,
      "manualPreSharedKey": <psk_value>,
      "policies": [
          {
              "name": <ike_policy_name>,
              "id": <ike_policy_uuid>,
              "type": "IKEv2Policy"
          }
      ]
  },
  "id": "",
  "type": "IkeSetting"
}
```

***Response:***

**Status Code:** `201` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "metadata": {
    "parentPolicy": {
      "name": "FTDS2SVpn",
      "id": "00505697-B8D7-0ed3-0000-111669150196",
      "type": "Test_Policy_1"
    },
    "timestamp": 1690293098757,
    "lastUser": {
      "name": "dcloud"
    },
    "domain": {
      "name": "Global",
      "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
      "type": "Domain"
    }
  },
  "links": {
    "self": "<ref_link>"
  },
  "id": "005056A9-7483-0ed3-0000-012884902862",
  "type": "IkeSetting",
  "ikeV2Settings": {
    "authenticationType": "MANUAL_PRE_SHARED_KEY",
    "manualPreSharedKey": "<psk_value>",
    "enforceHexBasedPreSharedKeyOnly": false,
    "policies": [
      {
        "name": "DES-SHA-SHA-LATEST",
        "id": "00505697-B8D7-0ed3-0000-000000000404",
        "type": "IKEv2Policy"
      }
    ]
  }
}
```

[Return to ToC](#table-of-contents)

---

### Configure Endpoint Node A (FTD Device)

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/policy_ftds2svpns/<s2s_policy_uuid>/endpoints` </br>
**Method:** `POST` </br>
**Headers:**
```json
{
    "Content-Type": "application/json",
    "X-auth-access-token": "<token>"
}
``` 

**Payload:**
```json
{
  "peerType": "PEER",
  "device": {
    "name": "<device_name>",
    "id": "<device_uuid>",
    "type": "Device"
  },
  "interface": {
    "name": "<device_interface_name>",
    "id": "<device_interface_uuid>",
    "type": "PhysicalInterface"
  },
  "protectedNetworks": {
    "networks": [
      {
        "name": "<network_object_name>",
        "id": "<network_object_uuid>",
        "type": "Network"
      }
    ]
  },
  "connectionType": "BIDIRECTIONAL",
  "isLocalTunnelIdEnabled": false,
  "type": "EndPoint",
  "overrideRemoteVpnFilter": false
}
```

***Response:***

**Status Code:** `201` </br>
**Headers:** N/A </br>
**Payload:**
```json
[
  {
    "metadata": {
      "parentPolicy": {
        "name": "FTDS2SVpn",
        "id": "00505697-B8D7-0ed3-0000-111669151230",
        "type": "Test_Policy_1"
      },
      "timestamp": 1690215351253,
      "lastUser": {
        "name": "dcloud"
      },
      "domain": {
        "name": "Global",
        "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
        "type": "Domain"
      }
    },
    "links": {
      "self": "<ref_link>"
    },
    "interface": {
      "name": "Inside_Interface",
      "id": "00505697-B8D7-0ed3-0000-111669149790",
      "type": "PhysicalInterface"
    },
    "id": "00505697-B8D7-0ed3-0000-111669151900",
    "isLocalTunnelIdEnabled": false,
    "extranet": false,
    "connectionType": "BIDIRECTIONAL",
    "device": {
      "name": "FTD",
      "id": "289140c4-2369-11ea-938e-91f922b309a7",
      "type": "Device"
    },
    "overrideRemoteVpnFilter": false,
    "peerType": "PEER",
    "protectedNetworks": {
      "networks": [
        {
          "name": "10.10.10.0_24",
          "id": "00505697-B8D7-0ed3-0000-111669151524",
          "type": "Network"
        }
      ]
    },
    "dynamicRRIEnabled": false,
    "name": "FTD",
    "type": "EndPoint"
  }
]
```

[Return to ToC](#table-of-contents)

---

### Configure Endpoint Node B (Remote Device)

***Request:***

**URI:** </br>
`https://<fmc_server>/api/fmc_config/v1/domain/<domain_uuid>/policy_ftds2svpns/<s2s_policy_uuid>/endpoints` </br>
**Method:** `POST` </br>
**Headers:**
```json
{
    "Content-Type": "application/json",
    "X-auth-access-token": "<token>"
}
``` 

**Payload:**
```json
{
  "peerType": "PEER",
  "extranetType": "GENERIC",
  "dynamicRRIEnabled": false,
  "connectionType": "ORIGINATE_ONLY",
  "isLocalTunnelIdEnabled": false,
  "type": "EndPoint",
  "name": "<node_b_name>",
  "extranet": true,
  "extranetInfo": {
    "name": "<node_b_name>",
    "ipAddress": "<node_b_ip>",
    "isDynamicIP": false
  },
  "protectedNetworks": {
    "networks": [
      {
        "name": "<network_object_name>",
        "id": "<network_object_uuid>",
        "type": "Network"
      }
    ]
  },
  "overrideRemoteVpnFilter": false
}
```

***Response:***

**Status Code:** `201` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "metadata": {
    "parentPolicy": {
      "name": "FTDS2SVpn",
      "id": "00505697-B8D7-0ed3-0000-111669151230",
      "type": "Test_Policy_1"
    },
    "timestamp": 1690222109986,
    "lastUser": {
      "name": "dcloud"
    },
    "domain": {
      "name": "Global",
      "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
      "type": "Domain"
    }
  },
  "links": {
    "self": "<ref_link>"
  },
  "id": "00505697-B8D7-0ed3-0000-111669151968",
  "isLocalTunnelIdEnabled": false,
  "extranet": true,
  "connectionType": "ORIGINATE_ONLY",
  "overrideRemoteVpnFilter": false,
  "peerType": "PEER",
  "protectedNetworks": {
    "networks": [
      {
        "name": "192.168.10.0_24",
        "id": "00505697-B8D7-0ed3-0000-111669151542",
        "type": "Network"
      }
    ]
  },
  "extranetType": "GENERIC",
  "dynamicRRIEnabled": false,
  "extranetInfo": {
    "name": "Node_B_Endpoint",
    "ipAddress": "192.168.10.1",
    "isDynamicIP": false
  },
  "name": "Node_B_Endpoint",
  "type": "EndPoint"
}
```

[Return to ToC](#table-of-contents)

---

### Get Site to Site VPN Policy Config

***Request:***

**URI:** </br>
`https://<fmc_server/api/fmc_config/v1/domain/<domain_uuid>/policy/ftds2svpns/<s2s_policy_uuid>` </br>
**Method:** `GET` </br>
**Headers:**
```json
{
    "Content-Type": "application/json",
    "X-auth-access-token": "<token>"
}
``` 

***Response:***

**Status Code:** `200` </br>
**Headers:** N/A </br>
**Payload:**
```json
{
  "advancedSettings": {
    "advancedIkeSetting": {
      "cookieChallenge": "CUSTOM",
      "enableAggressiveMode": false,
      "enableNotificationOnTunnelDisconnect": false,
      "identitySentToPeer": "AUTO_OR_DN",
      "ikeKeepaliveSettings": {
        "ikeKeepalive": "ENABLED",
        "retryInterval": 2,
        "threshold": 10
      },
      "peerIdentityValidation": "REQUIRED",
      "percentageOfSAsAllowedInNegotiation": 100,
      "thresholdToChallengeIncomingCookies": 50
    },
    "advancedIpsecSetting": {
      "enableFragmentationBeforeEncryption": true,
      "maximumTransmissionUnitAging": {
        "enabled": false
      }
    },
    "advancedTunnelSetting": {
      "bypassAccessControlTrafficForDecryptedTraffic": false,
      "certificateMapSettings": {
        "useCertMapConfiguredInEndpointToDetermineTunnel": false,
        "useCertificateOuToDetermineTunnel": true,
        "useIkeIdentityOuToDetermineTunnel": true,
        "usePeerIpAddressToDetermineTunnel": true
      },
      "enableSpokeToSpokeConnectivityThroughHub": false,
      "natKeepaliveMessageTraversal": {
        "enabled": true,
        "intervalSeconds": 20
      }
    },
    "id": "005056A9-7483-0ed3-0000-012884902864",
    "links": {
      "self": "<ref_link>"
    },
    "type": "AdvancedSetting"
  },
  "endpoints": {
    "links": {
      "self": "<ref_link>"
    },
    "refType": "list",
    "type": "EndPoint"
  },
  "id": "00505697-B8D7-0ed3-0000-111669152550",
  "ikeSettings": {
    "id": "005056A9-7483-0ed3-0000-012884902862",
    "links": {
      "self": "<ref_link>"
    },
    "type": "IkeSetting"
  },
  "ikeV1Enabled": true,
  "ikeV2Enabled": false,
  "ipsecSettings": {
    "cryptoMapType": "STATIC",
    "doNotFragmentPolicy": "NONE",
    "enableRRI": true,
    "enableSaStrengthEnforcement": false,
    "id": "005056A9-7483-0ed3-0000-012884902863",
    "ikeV1IpsecProposal": [
      {
        "id": "00505697-B8D7-0ed3-0000-000000002003",
        "name": "tunnel_aes256_sha",
        "type": "IKEv1IPsecProposal"
      }
    ],
    "ikeV2Mode": "TUNNEL",
    "lifetimeKilobytes": 4608000,
    "lifetimeSeconds": 28800,
    "links": {
      "self": "<ref_link>"
    },
    "perfectForwardSecrecy": {
      "enabled": false
    },
    "tfcPackets": {
      "burstBytes": 0,
      "enabled": false,
      "payloadBytes": 0,
      "timeoutSeconds": 0
    },
    "type": "IPSecSetting",
    "validateIncomingIcmpErrorMessage": false
  },
  "links": {
    "self": "<ref_link>"
  },
  "metadata": {
    "domain": {
      "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
      "name": "Global",
      "type": "Domain"
    },
    "lastUser": {
      "name": "dcloud"
    },
    "timestamp": 1690836164697
  },
  "name": "Test_Policy_2",
  "routeBased": false,
  "topologyType": "POINT_TO_POINT",
  "type": "FTDS2SVpn"
}
```

[Return to ToC](#table-of-contents)

---