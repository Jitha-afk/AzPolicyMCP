import requests
import logging
import json
import jsonschema
import os
from typing import Optional, List, Dict, Any, Literal, Union
import httpx
from contextlib import asynccontextmanager
from dataclasses import dataclass
import msal

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from mcp.server.fastmcp import FastMCP, Context

# --- Application Context for Authentication ---
@dataclass
class AppContext:
    msal_app: Any = None

@asynccontextmanager
async def app_lifespan(server: FastMCP):
    """Initialize MSAL application on startup for Azure API authentication"""
    try:
        # Check for required environment variables
        tenant_id = os.environ.get("TENANT_ID")
        client_id = os.environ.get("CLIENT_ID")
        client_secret = os.environ.get("CLIENT_SECRET")

        if not all([tenant_id, client_id, client_secret]):
            logger.warning("Azure authentication environment variables not found. Policy deployment features will be unavailable.")
            yield AppContext(msal_app=None)
            return

        # Initialize MSAL application
        msal_config = {
            "authority": f"https://login.microsoftonline.com/{tenant_id}",
            "client_id": client_id,
            "client_credential": client_secret,
        }

        msal_app = msal.ConfidentialClientApplication(**msal_config)
        logger.info("MSAL application initialized successfully")
        
        yield AppContext(msal_app=msal_app)
    except Exception as e:
        logger.error(f"Error initializing Azure authentication: {str(e)}")
        yield AppContext(msal_app=None)

# Initialize the MCP server
mcp = FastMCP(
    "AzurePolicyServer",
    description="MCP Server for interacting with Azure Policy definitions.",
    # Add dependencies that should be installed if the server is installed via 'mcp install'
    dependencies=["requests", "jsonschema", "httpx", "msal"],
    lifespan=app_lifespan
)

# --- Resource Definitions ---
# Example: Expose the Azure Policy schema maybe?
# @mcp.resource("azurepolicy://schema")
# def get_policy_schema():
#     # Load and return the schema JSON
#     pass

# --- Tool Definitions ---
GITHUB_API_BASE = "https://api.github.com"
POLICY_REPO = "Azure/azure-policy"
POLICY_DEFINITIONS_PATH = "built-in-policies/policyDefinitions"

@mcp.tool()
def get_builtin_policies(query: Optional[str] = None) -> List[Dict[str, str]] | str:
    """
    Fetches built-in Azure Policy definitions from the official Azure/azure-policy GitHub repository.

    Args:
        query: An optional string to filter policy names.

    Returns:
        A list of dictionaries containing policy names and their paths, or an error message string.
        Note: GitHub API rate limits may apply to unauthenticated requests.
    """
    api_url = f"{GITHUB_API_BASE}/repos/{POLICY_REPO}/contents/{POLICY_DEFINITIONS_PATH}"
    logger.info(f"Fetching policy definitions from: {api_url}")

    try:
        response = requests.get(api_url, timeout=10) # Add a timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        content = response.json()
        if not isinstance(content, list):
            logger.error(f"Unexpected response format from GitHub API: {type(content)}")
            return "Error: Unexpected response format from GitHub API."

        policies = [
            {"name": item["name"], "path": item["path"]}
            for item in content
            if item["type"] == "dir" # We are interested in the category directories first
        ]

        # Basic filtering by directory name (category)
        if query:
            query_lower = query.lower()
            policies = [p for p in policies if query_lower in p["name"].lower()]

        if not policies:
             return f"No policy categories found matching query: '{query}'" if query else "No policy categories found."

        return policies

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching policies from GitHub: {e}", exc_info=True)
        return f"Error: Failed to fetch policies from GitHub. {e}"
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return f"Error: An unexpected error occurred. {e}"


@mcp.tool()
def get_policies_in_category(
    category_path: str, query: Optional[str] = None
) -> List[Dict[str, str]] | str:
    """
    Fetches the names and download URLs of policy definition JSON files within a specific category
    from the Azure/azure-policy GitHub repository.

    Args:
        category_path: The path to the category directory (e.g., 'built-in-policies/policyDefinitions/Storage')
                       obtained from the 'get_builtin_policies' tool.
        query: An optional string to filter policy names within the category.

    Returns:
        A list of dictionaries containing policy file names and their download URLs, or an error message string.
        Note: GitHub API rate limits may apply.
    """
    if not category_path.startswith(POLICY_DEFINITIONS_PATH):
        return f"Error: Invalid category path. Path must start with '{POLICY_DEFINITIONS_PATH}'."

    api_url = f"{GITHUB_API_BASE}/repos/{POLICY_REPO}/contents/{category_path}"
    logger.info(f"Fetching policies within category: {api_url}")

    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()

        content = response.json()
        if not isinstance(content, list):
            logger.error(f"Unexpected response format for category content: {type(content)}")
            return "Error: Unexpected response format from GitHub API for category content."

        policy_files = [
            {
                "name": item["name"],
                "download_url": item["download_url"],
                "path": item["path"], # Include path for potential future use
            }
            for item in content
            if item["type"] == "file" and item["name"].endswith(".json")
        ]

        # Filter by policy file name
        if query:
            query_lower = query.lower()
            policy_files = [p for p in policy_files if query_lower in p["name"].lower()]

        if not policy_files:
            return f"No policy definition files found in '{category_path}' matching query: '{query}'" if query else f"No policy definition files found in '{category_path}'."

        return policy_files

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching policies from category '{category_path}': {e}", exc_info=True)
        return f"Error: Failed to fetch policies from category '{category_path}'. {e}"
    except Exception as e:
        logger.error(f"An unexpected error occurred fetching category '{category_path}': {e}", exc_info=True)
        return f"Error: An unexpected error occurred fetching category '{category_path}'. {e}"


@mcp.tool()
def get_policy_content(download_url: str) -> str:
    """
    Fetches the raw JSON content of a specific policy definition file using its download URL.

    Args:
        download_url: The direct download URL for the policy JSON file,
                      obtained from the 'get_policies_in_category' tool.

    Returns:
        The raw policy definition JSON as a string, or an error message string.
    """
    if not download_url or not download_url.startswith("https://raw.githubusercontent.com/"):
        return "Error: Invalid download URL provided."

    logger.info(f"Fetching policy content from: {download_url}")

    try:
        response = requests.get(download_url, timeout=10)
        response.raise_for_status() # Check for HTTP errors

        # Return the raw text content (which should be JSON)
        return response.text

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching policy content from {download_url}: {e}", exc_info=True)
        return f"Error: Failed to fetch policy content from {download_url}. {e}"
    except Exception as e:
        logger.error(f"An unexpected error occurred fetching policy content from {download_url}: {e}", exc_info=True)
        return f"Error: An unexpected error occurred fetching policy content. {e}"


# -- Schema Validation --
POLICY_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schemas", "policyDefinition.json")
_policy_schema = None

def load_policy_schema() -> Dict[str, Any] | None:
    """Loads the policy definition schema from the local file."""
    global _policy_schema
    if (_policy_schema is None):
        try:
            logger.info(f"Loading policy schema from: {POLICY_SCHEMA_PATH}")
            with open(POLICY_SCHEMA_PATH, 'r', encoding='utf-8') as f:
                _policy_schema = json.load(f)
            logger.info("Policy schema loaded successfully.")
        except FileNotFoundError:
            logger.error(f"Schema file not found at: {POLICY_SCHEMA_PATH}")
            _policy_schema = {} # Indicate failure but avoid repeated attempts
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding schema JSON from {POLICY_SCHEMA_PATH}: {e}", exc_info=True)
            _policy_schema = {} # Indicate failure
        except Exception as e:
            logger.error(f"Unexpected error loading schema: {e}", exc_info=True)
            _policy_schema = {} # Indicate failure
    return _policy_schema if _policy_schema else None


# @mcp.tool()
# def verify_policy_structure(policy_json_string: str) -> str:
#     """
#     Validates the structure of a given Azure Policy definition JSON string against the official schema.

#     Args:
#         policy_json_string: A string containing the Azure Policy definition in JSON format.

#     Returns:
#         A success message if the policy is valid, or a detailed error message if validation fails.
#     """
#     schema = load_policy_schema()
#     if schema is None:
#         return "Error: Could not load the Azure Policy schema for validation."

#     try:
#         policy_data = json.loads(policy_json_string)
#     except json.JSONDecodeError as e:
#         logger.error(f"Invalid JSON provided for validation: {e}", exc_info=True)
#         return f"Error: Invalid JSON format provided. Details: {e}"
#     except Exception as e:
#         logger.error(f"An unexpected error occurred parsing policy JSON: {e}", exc_info=True)
#         return f"Error: An unexpected error occurred while parsing the policy JSON. {e}"

#     try:
#         # Define the properties part of the policy if it exists
#         policy_rule = policy_data.get('properties', {}).get('policyRule')
#         if not policy_rule:
#              return "Error: Policy JSON is missing the 'properties.policyRule' structure."

#         # Validate the policyRule part against the schema
#         jsonschema.validate(instance=policy_rule, schema=schema)
#         logger.info("Policy structure validation successful.")
#         return "Success: Policy structure is valid according to the schema."

#     except jsonschema.exceptions.ValidationError as e:
#         logger.warning(f"Policy structure validation failed: {e.message}")
#         # Provide more context from the validation error
#         error_details = f"Validation Error: {e.message}\nPath: {list(e.path)}"
#         if e.context:
#              error_details += f"\nContext: {[(ctx.message, list(ctx.path)) for ctx in e.context]}"
#         return f"Error: Policy structure is invalid. Details: {error_details}"
#     except Exception as e:
#         logger.error(f"An unexpected error occurred during schema validation: {e}", exc_info=True)
#         return f"Error: An unexpected error occurred during schema validation. {e}"

# -- Azure Policy Assignment Tools --

@mcp.tool()
async def deploy_policy_assignment(
    scope: str,
    policy_assignment_name: str,
    display_name: str,
    description: str,
    policy_definition_id: str,
    non_compliance_message: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    enforcement_mode: Optional[Literal["Default", "DoNotEnforce"]] = "Default",
    ctx: Context = None
) -> str:
    """
    Creates or updates an Azure Policy Assignment using the Azure Management REST API.
    
    Args:
        scope: The scope where the policy will be assigned. Must be one of the following patterns:
               - Management group: '/providers/Microsoft.Management/managementGroups/{managementGroup}'
               - Subscription: '/subscriptions/{subscriptionId}'
               - Resource group: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
               - Resource: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'
        policy_assignment_name: The name for the policy assignment (becomes part of the policyAssignmentId)
        display_name: A user-friendly display name for the policy assignment
        description: A description that provides context about the policy assignment
        policy_definition_id: The ID of the policy definition to assign (e.g., '/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d')
        non_compliance_message: Optional message to display when resources are non-compliant
        parameters: Optional dictionary of parameters for the policy assignment
        enforcement_mode: Whether the policy should be enforced or monitored only (Default=enforced, DoNotEnforce=audit only)
        ctx: MCP context object
    
    Returns:
        A success message with assignment details, or an error message if the assignment failed
    """
    try:
        # Verify Azure authentication is available
        if ctx is None or ctx.request_context.lifespan_context is None or ctx.request_context.lifespan_context.msal_app is None:
            return "Error: Azure authentication is not available. Please ensure TENANT_ID, CLIENT_ID, and CLIENT_SECRET environment variables are set."

        # Get the MSAL app from lifespan context
        msal_app = ctx.request_context.lifespan_context.msal_app

        # Validate scope format
        valid_scope_patterns = [
            r'/providers/Microsoft\.Management/managementGroups/\w+',
            r'/subscriptions/[\w-]+',
            r'/subscriptions/[\w-]+/resourceGroups/[\w-]+',
            r'/subscriptions/[\w-]+/resourceGroups/[\w-]+/providers/.+'
        ]
        
        # Note: In a production environment, implement proper regex validation 
        # for the scope patterns above

        # Acquire token for Azure Management API
        token_response = msal_app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        
        if "access_token" not in token_response:
            error_msg = f"Failed to acquire access token: {token_response.get('error_description', '')}"
            logger.error(error_msg)
            return error_msg

        # Prepare the request body for policy assignment
        request_body = {
            "properties": {
                "displayName": display_name,
                "description": description,
                "policyDefinitionId": policy_definition_id,
                "enforcementMode": enforcement_mode
            }
        }
        
        # Add non-compliance message if provided
        if non_compliance_message:
            request_body["properties"]["nonComplianceMessages"] = [
                {"message": non_compliance_message}
            ]
        
        # Add parameters if provided
        if parameters:
            request_body["properties"]["parameters"] = parameters
        
        # Prepare the API URL and headers
        api_version = "2023-04-01"  # Using the latest API version as of the documentation
        url = f"https://management.azure.com{scope}/providers/Microsoft.Authorization/policyAssignments/{policy_assignment_name}"
        
        headers = {
            "Authorization": f"Bearer {token_response['access_token']}",
            "Content-Type": "application/json"
        }
        
        # Make the API request to create/update the policy assignment
        async with httpx.AsyncClient() as client:
            response = await client.put(
                url,
                params={"api-version": api_version},
                headers=headers,
                json=request_body
            )
            
            # Handle response
            try:
                response_data = response.json() if response.text else {}
            except json.JSONDecodeError:
                response_data = {"rawResponse": response.text}
            
            if response.status_code >= 400:
                logger.error(f"Policy assignment error: {response_data}")
                return f"Error creating policy assignment ({response.status_code}): {json.dumps(response_data, indent=2)}"

            # Format successful response
            result = (
                f"Policy assignment successfully created:\n"
                f"- Name: {policy_assignment_name}\n"
                f"- Scope: {scope}\n"
                f"- Policy Definition ID: {policy_definition_id}\n\n"
                f"Full response:\n{json.dumps(response_data, indent=2)}"
            )
            
            return result

    except Exception as error:
        logger.error(f"Error in deploy_policy_assignment: {error}", exc_info=True)
        return f"Error deploying policy assignment: {str(error)}"


@mcp.tool()
async def query_policy_compliance(
    scope: str,
    policy_assignment_name: Optional[str] = None,
    compliance_state: Optional[Literal["Compliant", "NonCompliant"]] = None,
    ctx: Context = None
) -> str:
    """
    Queries the compliance state of resources against assigned policies using the Azure PolicyInsights REST API.
    
    Args:
        scope: The scope to query for policy compliance. Must be one of the following patterns:
               - Subscription: '/subscriptions/{subscriptionId}'
               - Resource group: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
        policy_assignment_name: Optional name of a specific policy assignment to filter results
        compliance_state: Optional filter for compliance state ('Compliant' or 'NonCompliant')
        ctx: MCP context object
    
    Returns:
        A formatted list of compliance results or an error message
    """
    try:
        # Verify Azure authentication is available
        if ctx is None or ctx.request_context.lifespan_context is None or ctx.request_context.lifespan_context.msal_app is None:
            return "Error: Azure authentication is not available. Please ensure TENANT_ID, CLIENT_ID, and CLIENT_SECRET environment variables are set."

        # Get the MSAL app from lifespan context
        msal_app = ctx.request_context.lifespan_context.msal_app
        
        # Acquire token for Azure Management API
        token_response = msal_app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        
        if "access_token" not in token_response:
            error_msg = f"Failed to acquire access token: {token_response.get('error_description', '')}"
            logger.error(error_msg)
            return error_msg
            
        # Build filter parameter if filters are provided
        filter_parts = []
        if compliance_state:
            filter_parts.append(f"complianceState eq '{compliance_state}'")
        if policy_assignment_name:
            filter_parts.append(f"PolicyAssignmentName eq '{policy_assignment_name}'")
            
        filter_param = " and ".join(filter_parts) if filter_parts else None
        
        # Prepare the API URL and headers
        api_version = "2019-10-01"  # Using the version from the documentation
        url = f"https://management.azure.com{scope}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
        
        headers = {
            "Authorization": f"Bearer {token_response['access_token']}",
            "Content-Type": "application/json"
        }
        
        # Prepare query parameters
        params = {"api-version": api_version}
        if filter_param:
            params["$filter"] = filter_param
            
        # Make the API request to query policy compliance
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                params=params,
                headers=headers
            )
            
            # Handle response
            try:
                response_data = response.json() if response.text else {}
            except json.JSONDecodeError:
                response_data = {"rawResponse": response.text}
            
            if response.status_code >= 400:
                logger.error(f"Policy compliance query error: {response_data}")
                return f"Error querying policy compliance ({response.status_code}): {json.dumps(response_data, indent=2)}"

            # Extract and format results
            results = response_data.get("value", [])
            count = response_data.get("@odata.count", 0)
            
            if count == 0:
                return f"No {compliance_state or ''} resources found for the specified criteria."
                
            # Format a summarized response
            result_text = f"Found {count} {compliance_state or ''} resource(s):\n\n"
            
            for item in results:
                result_text += (
                    f"Resource: {item.get('resourceId', 'Unknown')}\n"
                    f"Compliance State: {item.get('complianceState', 'Unknown')}\n"
                    f"Policy Assignment: {item.get('policyAssignmentName', 'Unknown')}\n"
                    f"Policy Definition: {item.get('policyDefinitionName', 'Unknown')}\n"
                    f"Timestamp: {item.get('timestamp', 'Unknown')}\n\n"
                )
            
            return result_text

    except Exception as error:
        logger.error(f"Error in query_policy_compliance: {error}", exc_info=True)
        return f"Error querying policy compliance: {str(error)}"


@mcp.tool()
async def delete_policy_assignment(
    scope: str,
    policy_assignment_name: str,
    ctx: Context = None
) -> str:
    """
    Deletes an Azure Policy Assignment using the Azure Management REST API.
    
    Args:
        scope: The scope from which to delete the policy assignment. Must be one of the following patterns:
               - Management group: '/providers/Microsoft.Management/managementGroups/{managementGroup}'
               - Subscription: '/subscriptions/{subscriptionId}'
               - Resource group: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
               - Resource: '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}'
        policy_assignment_name: The name of the policy assignment to delete
        ctx: MCP context object
    
    Returns:
        A success message, or an error message if the deletion failed
    """
    try:
        # Verify Azure authentication is available
        if ctx is None or ctx.request_context.lifespan_context is None or ctx.request_context.lifespan_context.msal_app is None:
            return "Error: Azure authentication is not available. Please ensure TENANT_ID, CLIENT_ID, and CLIENT_SECRET environment variables are set."

        # Get the MSAL app from lifespan context
        msal_app = ctx.request_context.lifespan_context.msal_app
        
        # Acquire token for Azure Management API
        token_response = msal_app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        
        if "access_token" not in token_response:
            error_msg = f"Failed to acquire access token: {token_response.get('error_description', '')}"
            logger.error(error_msg)
            return error_msg
        
        # Prepare the API URL and headers
        api_version = "2023-04-01"  # Using the latest API version as of the documentation
        url = f"https://management.azure.com{scope}/providers/Microsoft.Authorization/policyAssignments/{policy_assignment_name}"
        
        headers = {
            "Authorization": f"Bearer {token_response['access_token']}",
            "Content-Type": "application/json"
        }
        
        # Make the API request to delete the policy assignment
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                url,
                params={"api-version": api_version},
                headers=headers
            )
            
            # Special case for successful deletions (204 No Content or 200 OK)
            if response.status_code in [204, 200]:
                return f"Policy assignment '{policy_assignment_name}' was successfully deleted from scope '{scope}'."
                
            # Handle error responses
            try:
                response_data = response.json() if response.text else {}
            except json.JSONDecodeError:
                response_data = {"rawResponse": response.text}
            
            return f"Error deleting policy assignment ({response.status_code}): {json.dumps(response_data, indent=2)}"

    except Exception as error:
        logger.error(f"Error in delete_policy_assignment: {error}", exc_info=True)
        return f"Error deleting policy assignment: {str(error)}"


@mcp.tool()
async def create_policy_definition(
    subscription_id: str,
    policy_definition_name: str,
    display_name: str,
    description: str,
    mode: Literal["All", "Indexed", "Microsoft.KeyVault.Data", "Microsoft.Kubernetes.Data"] = "All",
    metadata: Optional[Dict[str, Any]] = None,
    parameters: Optional[Dict[str, Dict[str, Any]]] = None,
    policy_rule: Dict[str, Any] = None,
    policy_type: Literal["Custom", "BuiltIn", "Static", "NotSpecified"] = "Custom",
    ctx: Context = None
) -> str:
    """
    Creates or updates an Azure Policy Definition using the Azure Management REST API.
    
    Args:
        subscription_id: The ID of the target subscription.
        policy_definition_name: The name of the policy definition to create. Must match pattern: ^[^<>*%&:\?.+/]*[^<>*%&:\?.+/ ]+$
        display_name: A user-friendly display name for the policy definition.
        description: A description that provides context about the policy definition.
        mode: The policy definition mode. Default is 'All'. Some other examples are 'Indexed', 'Microsoft.KeyVault.Data'.
        metadata: Optional metadata for the policy definition, typically a collection of key-value pairs.
        parameters: Optional parameter definitions for parameters used in the policy rule.
        policy_rule: The policy rule object containing the 'if' condition and 'then' action.
        policy_type: The type of policy definition. Default is 'Custom'. Other options are 'BuiltIn', 'Static', 'NotSpecified'.
        ctx: MCP context object
    
    Returns:
        A success message with definition details, or an error message if the creation failed
    """
    try:
        # Verify Azure authentication is available
        if ctx is None or ctx.request_context.lifespan_context is None or ctx.request_context.lifespan_context.msal_app is None:
            return "Error: Azure authentication is not available. Please ensure TENANT_ID, CLIENT_ID, and CLIENT_SECRET environment variables are set."

        # Get the MSAL app from lifespan context
        msal_app = ctx.request_context.lifespan_context.msal_app
        
        # Acquire token for Azure Management API
        token_response = msal_app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
        
        if "access_token" not in token_response:
            error_msg = f"Failed to acquire access token: {token_response.get('error_description', '')}"
            logger.error(error_msg)
            return error_msg

        # Prepare the request body for policy definition
        request_body = {
            "properties": {
                "displayName": display_name,
                "description": description,
                "mode": mode,
                "policyType": policy_type,
            }
        }
        
        # Add optional properties if provided
        if metadata:
            request_body["properties"]["metadata"] = metadata
        
        if parameters:
            request_body["properties"]["parameters"] = parameters
        
        if policy_rule:
            request_body["properties"]["policyRule"] = policy_rule
        
        # Prepare the API URL and headers
        api_version = "2023-04-01"
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyDefinitions/{policy_definition_name}"
        
        headers = {
            "Authorization": f"Bearer {token_response['access_token']}",
            "Content-Type": "application/json"
        }
        
        # Make the API request to create/update the policy definition
        async with httpx.AsyncClient() as client:
            response = await client.put(
                url,
                params={"api-version": api_version},
                headers=headers,
                json=request_body
            )
            
            # Handle response
            try:
                response_data = response.json() if response.text else {}
            except json.JSONDecodeError:
                response_data = {"rawResponse": response.text}
            
            if response.status_code >= 400:
                logger.error(f"Policy definition error: {response_data}")
                return f"Error creating policy definition ({response.status_code}): {json.dumps(response_data, indent=2)}"
            
            # Extract the policy definition ID from the response for use in assignments
            policy_definition_id = response_data.get("id")
            
            # Format successful response
            result = (
                f"Policy definition successfully created:\n"
                f"- Name: {policy_definition_name}\n"
                f"- Display Name: {display_name}\n"
                f"- Policy Definition ID: {policy_definition_id}\n\n"
                f"Full response:\n{json.dumps(response_data, indent=2)}"
            )
            
            return result

    except Exception as error:
        logger.error(f"Error in create_policy_definition: {error}", exc_info=True)
        return f"Error creating policy definition: {str(error)}"


# --- Run the server (for direct execution) ---
if __name__ == "__main__":
    load_policy_schema() # Attempt to load schema on startup
    mcp.run()
