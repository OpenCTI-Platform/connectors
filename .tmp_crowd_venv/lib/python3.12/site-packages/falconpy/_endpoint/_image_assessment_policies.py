"""Internal API endpoint constant library.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

_image_assessment_policies_endpoints = [
  [
    "ReadPolicies",
    "GET",
    "/container-security/entities/image-assessment-policies/v1",
    "Get all Image Assessment policies",
    "image_assessment_policies",
    []
  ],
  [
    "CreatePolicies",
    "POST",
    "/container-security/entities/image-assessment-policies/v1",
    "Create Image Assessment policies",
    "image_assessment_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdatePolicies",
    "PATCH",
    "/container-security/entities/image-assessment-policies/v1",
    "Update Image Assessment Policy entities",
    "image_assessment_policies",
    [
      {
        "type": "string",
        "description": "Image Assessment Policy entity UUID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeletePolicy",
    "DELETE",
    "/container-security/entities/image-assessment-policies/v1",
    "Delete Image Assessment Policy by policy UUID",
    "image_assessment_policies",
    [
      {
        "type": "string",
        "description": "Image Assessment Policy entity UUID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "ReadPolicyExclusions",
    "GET",
    "/container-security/entities/image-assessment-policy-exclusions/v1",
    "Retrieve Image Assessment Policy Exclusion entities",
    "image_assessment_policies",
    []
  ],
  [
    "UpdatePolicyExclusions",
    "POST",
    "/container-security/entities/image-assessment-policy-exclusions/v1",
    "Update Image Assessment Policy Exclusion entities",
    "image_assessment_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "ReadPolicyGroups",
    "GET",
    "/container-security/entities/image-assessment-policy-groups/v1",
    "Retrieve Image Assessment Policy Group entities",
    "image_assessment_policies",
    []
  ],
  [
    "CreatePolicyGroups",
    "POST",
    "/container-security/entities/image-assessment-policy-groups/v1",
    "Create Image Assessment Policy Group entities",
    "image_assessment_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "UpdatePolicyGroups",
    "PATCH",
    "/container-security/entities/image-assessment-policy-groups/v1",
    "Update Image Assessment Policy Group entities",
    "image_assessment_policies",
    [
      {
        "type": "string",
        "description": "Policy Image Group entity UUID",
        "name": "id",
        "in": "query",
        "required": True
      },
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ],
  [
    "DeletePolicyGroup",
    "DELETE",
    "/container-security/entities/image-assessment-policy-groups/v1",
    "Delete Image Assessment Policy Group entities",
    "image_assessment_policies",
    [
      {
        "type": "string",
        "description": "Policy Image Group entity UUID",
        "name": "id",
        "in": "query",
        "required": True
      }
    ]
  ],
  [
    "UpdatePolicyPrecedence",
    "POST",
    "/container-security/entities/image-assessment-policy-precedence/v1",
    "Update Image Assessment Policy precedence",
    "image_assessment_policies",
    [
      {
        "name": "body",
        "in": "body",
        "required": True
      }
    ]
  ]
]
