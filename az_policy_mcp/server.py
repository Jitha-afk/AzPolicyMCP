from mcp.server.fastmcp import FastMCP

# Import tool functions when they are implemented
# from .policy_tools import get_builtin_policies, verify_policy_structure

# Create the FastMCP server instance
mcp = FastMCP(
    "Azure Policy Helper",
    description="MCP Server to assist with Azure Policy creation and validation.",
    # Define dependencies required if installing via 'mcp install'
    # Add 'requests' or 'GitPython' here if needed for get_builtin_policies
    dependencies=["jsonschema"],
)

# --- Tool Definitions ---

# @mcp.tool()
# def verify_policy_structure(policy_json: str) -> dict:
#     """Validate the structure of an Azure Policy JSON string against the official schema."""
#     # Implementation will be in policy_tools.py
#     return policy_tools.verify_policy_structure(policy_json)


# @mcp.tool()
# async def get_builtin_policies(query: str) -> list[dict]:
#     """Search the Azure built-in policies for relevant examples based on a query."""
#     # Implementation will be in policy_tools.py
#     # Mark as async if using async libraries like httpx or asyncio file IO
#     return await policy_tools.get_builtin_policies(query)


# --- Resource Definitions (Optional Enhancements) ---

# @mcp.resource("schema://azurepolicy")
# def get_azure_policy_schema() -> str:
#     """Get the official Azure Policy JSON schema."""
#     # Implementation to read schema file
#     pass

# --- Prompt Definitions (Optional Enhancements) ---

# @mcp.prompt()
# def create_policy_prompt(resource_type: str, requirement: str) -> str:
#     """Guide the LLM to create an Azure Policy."""
#     # Implementation of the prompt template
#     pass


# --- Server Runner ---


# Allows running the server directly using 'python az_policy_mcp/server.py'
if __name__ == "__main__":
    # Placeholder: Import the actual tool functions here before running
    # from .policy_tools import verify_policy_structure, get_builtin_policies
    # mcp.tool()(verify_policy_structure)
    # mcp.tool()(get_builtin_policies) # Adjust decorator if async

    print("Starting Azure Policy MCP Server...")
    print("Note: Tools are currently placeholders and not yet functional.")
    mcp.run() 