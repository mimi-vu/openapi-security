import re

# ------------------------ SECURITY 001  ------------------------

def sec001(spec):
    """
    SEC001 no global security
    """
    issues = []
    # see if there is security in root
    if "security" not in spec:
        issues.append({
            "rule_id": "SEC001",
            "severity": "Critical",
            "message": "No global security",
            "location": "root"
        })
    
    return issues


# ------------------------ SECURITY 002  ------------------------

def sec002(spec, details, path, method):
    """
    SEC002 unprotected endpoint 
    global + all endpoints are secure and prints insecure endpoints
    public end points are not secure
    """
    issues = []

    global_security = spec.get("security")

    # security at end points
    operation_security = details.get("security")

    if global_security is None and operation_security is None:
        issues.append({
            "rule_id": "SEC002",
            "severity": "High",
            "message": "Unprotected endpoint",
            "location": f"{path} > {method}"
        })

    # publicly accessible without auth
    elif operation_security == []:
        issues.append({
            "rule_id": "SEC002",
            "severity": "High",
            "message": "Endpoint explicitly marked as public",
            "location": f"{path} > {method}"
        })


    return issues


# ------------------------ SECURITY 003  ------------------------

def sec003(spec):
    """
    SEC003 http not allowed
    """
    issues = []

    # iterate through all servers
    if "servers" in spec:
        for server in spec["servers"]:
            if server.get("url", "").startswith("http://"):
                issues.append({
                    "rule_id": "SEC003",
                    "severity": "High",
                    "message": "HTTP protocol",
                    "location": "servers"
                })
    
    return issues


# ------------------------ SECURITY 004  ------------------------
def sec004(details, path, method):
    """
    SEC004 no rate limiting headers ~
    rate limiting prevents spamming requests prevent DoS attacks
    """

    responses = details.get("responses", {})
    has_rate_limit = False

    # for each response object
    for response in responses.values():

        issues = []
        headers = response.get("headers", {})

        # check if rate limit exists
        for header_name in headers.keys():
            if header_name.startswith("X-RateLimit-"):
                has_rate_limit = True
                break
        if has_rate_limit:
            break

    if not has_rate_limit:
        issues.append({
            "rule_id": "SEC004",
            "severity": "Medium",
            "message": "No rate limiting headers defined",
            "location": f"{path} > {method}"
        })
    return issues

# ------------------------ SECURITY 005  ------------------------
def sec005(params, method, path):
    """
    SEC005 sensitive query params
    if not a method, then get params
    """
    issues = []

    sensitive_keywords = ["password", "token", "secret", "api_key", "apikey", "auth"]

    for p in params:

        if p.get("in") == "query":
            name = p.get("name", "").lower()

            if any(k in name for k in sensitive_keywords):
                issues.append({
                    "rule_id": "SEC005",
                    "severity": "Medium",
                    "message": f"Sensitive data in query parameter '{name}' found in {method.upper()} request.",
                    "location": f"{path} > {method}"
                })  
    
    return issues

# ------------------------ SECURITY 006  ------------------------
def sec006(details, path, method):

    issues = []
    required_set = {"401", "403", "429"}
     # use set subtraction to find missing responses
    responses = details.get("responses", {})
    
    all_responses = set(responses.keys())

    missing_responses = required_set - all_responses

    if missing_responses:

        missing_str = ", ".join(list(missing_responses))
        issues.append({
            "rule_id": "SEC006",
            "severity": "Medium",
            "message": f"Missing status code(s): {missing_str}.",
            "location": f"{path} > {method}"
        })
    
    return issues

# ------------------------ SECURITY 007  ------------------------
def sec007(spec):

    """
    SEC007 missing info.contact or x-security-contact
    """

    issues = []
    info = spec.get("info", {})
    contact = info.get("contact", {})

    # contact or email missing
    if not contact:
        issues.append({
            "rule_id": "SEC007",
            "severity": "Low",
            "message": f"Contact is missing",
            "location": f"info.contact"
        })
    elif not contact.get("email"):
        issues.append({
            "rule_id": "SEC007",
            "severity": "Low",
            "message": f"Email is missing",
            "location": f"info.contact.email"
        })
    elif not info.get("x-security-contact"):
        issues.append({
            "rule_id": "SEC007",
            "severity": "Low",
            "message": f"security contact is missing",
            "location": f"info.contact.x-security-contact"
        })
    
    return issues

# ------------------------ SECURITY 008  ------------------------
def sec008(details, path, method):
    """
    SEC008 deprecated endpoint still documented~ 
    """

    issues = []
    if details.get("deprecated") is True:
        issues.append({
            "rule_id": "SEC008",
            "severity": "Low",
            "message": f"Deprecated endpoint",
            "location": f"{path} > {method}"
        })

    return issues

# ------------------------ SECURITY 009  ------------------------
# from gemini
def has_wildcards(s):
  """
  Checks if a string contains common wildcard characters (* or ?).
  """
  return '*' in s or '?' in s

def sec009(server_list, location_path):
    """
    This validates every url in server 
    """
    issues = []

    for server in server_list:
        url = server.get("url", "")
        variables = server.get("variables", {})

        # placeholders e.g. {env} that are not enums are wildcards
        placeholder_vars = re.findall(r"\{(.*?)\}", url)
        
        for v in placeholder_vars:
            var_def = variables.get(v, {})

            if not var_def.get("enum"):
                issues.append({
                    "rule_id": "SEC009",
                    "severity": "High",
                    "message": f"Server url: '{url}', contains unconstrained variable '{v}'.",
                    "location": f"{location_path}.servers"
                })


            if has_wildcards(url):
                issues.append({
                "rule_id": "SEC009",
                "severity": "High",
                "message": f"Server url '{url}' contains wildcard characters.",
                "location": f"{location_path}.servers"
            })
    
    return issues


def validate_schema(schema, validation_keys):

    """
    Recursive to 'leaf' (schema) and checks for validation criteria.
    """

    if not schema or not isinstance(schema, dict):
        return False
    
    # base case: see if the current level has ANY validation keys
    if any(key in schema for key in validation_keys):
        return True
    
    # If it's an object, check its properties and validate 
    if schema.get("type") == "object":
        properties = schema.get("properties", {})
        for prop_schema in properties.values():
            
            if validate_schema(prop_schema, validation_keys):
                return True
        
    # If it's an array, check the items
    if schema.get("type") == "array":
        return validate_schema(schema.get("items", {}), validation_keys)
        
    return False



def sec010(details, params, method, path):

    """
    No input validation - check if request body or parameter lack pattern,
    minLength, maxLength, minimum, maximum constraints
    """

    issues = []

    validation_keys = ["pattern", "minLength", "maxLength", "minimum", "maximum", "enum", "items"]

    # validate schema in each param
    for param in params:
        param_schema = param.get("schema", {})

        if not validate_schema(param_schema, validation_keys):
            issues.append({
                "rule_id": "SEC010",
                "severity": "Medium",
                "message": f"Parameter '{param.get('name')}' lacks input validation",
                "location": f"{path} > {method} > {param.get('name')}"
            })

    # validate request body
    request_body = details.get("requestBody", {})
    content = request_body.get("content", {})

    for media_type, media_details in content.items():
        body_schema = media_details.get("schema", {})


        if not validate_schema(body_schema, validation_keys):
            issues.append({
                "rule_id": "SEC010",
                "severity": "Medium",
                "message": f"Request body ({media_type}) lacks input validation constraints",
                "location": f"{path} > {method} > requestBody"
            })

    return issues


# ------------------------ MAIN FUNCITON ------------------------

def security_checks(spec):
    issues = []

    paths = spec.get("paths", {})

    # 001
    issues.extend(sec001(spec))

    # 003
    issues.extend(sec003(spec))
    
        
    for path, path_item in paths.items():

        # params at path level
        path_params = path_item.get("parameters", [])
        
        for method, details in path_item.items():
            
            # IF HTTP METHOD
            if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:

                # 002
                issues.extend(sec002(spec, details, path, method))

                # 004
                issues.extend(sec004(details, path, method))

                # 006
                issues.extend(sec006(details, path, method) )

            else:

                method_params = details.get("parameters", [])
                params = method_params + path_params
                # 005
                issues.extend(sec005(params, method, path))

                # 010 
                issues.extend(sec010(details, params, method, path))
            
            # 008
            issues.extend(sec008(details, path, method))
    
    # 007
    issues.extend(sec007(spec))
    
    # 009
    servers = spec.get("servers", [])

    # check global server
    issues.extend(sec009(servers, "root"))

    # check path overrides
    for path, path_item in spec.get("paths", {}).items():
        path_servers = path_item.get("servers", [])
        issues.extend(sec009(path_servers, f"paths.{path}"))
    
    

    return issues
