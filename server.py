import requests
import logging
import json
import jsonschema
import os
from typing import Optional, List, Dict, Any

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP(
    "AzurePolicyServer",
    description="MCP Server for interacting with Azure Policy definitions.",
    # Add dependencies that should be installed if the server is installed via 'mcp install'
    dependencies=["requests", "jsonschema"],
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
    if _policy_schema is None:
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

# --- Run the server (for direct execution) ---
if __name__ == "__main__":
    load_policy_schema() # Attempt to load schema on startup
    mcp.run() 