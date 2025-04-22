# Azure Policy MCP Server

This project provides a Model Context Protocol (MCP) server designed to help Large Language Models (LLMs) interact with Azure Policy. It offers tools to fetch built-in policy information, validate custom policies (currently disabled), and eventually deploy policy assignments.

## Features

The server currently provides the following MCP tools:

*   `get_builtin_policies(query: Optional[str] = None)`: Fetches the top-level categories of Azure built-in policies from the official `Azure/azure-policy` GitHub repository. Allows filtering by category name.
*   `get_policies_in_category(category_path: str, query: Optional[str] = None)`: Fetches individual policy definition files (name, path, download URL) within a specified category path.
*   `get_policy_content(download_url: str)`: Fetches the raw JSON content of a policy definition using its direct download URL.

Planned / In-Progress Features:

*   `verify_policy_structure(policy_json_string: str)`: (Currently Disabled) Validates a given policy JSON string against the official Azure Policy schema.
*   `deploy_policy_assignment(...)`: (Planned) Deploys a policy definition as an assignment in Azure using the REST API.
*   Intent Identification Support: (Planned) Features to help the LLM determine user intent (Audit/Deny vs. Remediate).

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    ```

3.  **Install Dependencies:**
    This project uses `requests` for API calls and `jsonschema` for validation. The `mcp` library is the core dependency.
    ```bash
    # Assuming you have a requirements.txt or will create one:
    pip install "mcp[cli]" requests jsonschema
    # (Optional, for planned features)
    # pip install azure-identity
    ```
    *Alternatively, if using `uv`:*
    ```bash
    uv pip install "mcp[cli]" requests jsonschema
    # (Optional, for planned features)
    # uv pip install azure-identity
    ```

4.  **Schema File:**
    Ensure the `schemas/policyDefinition.json` file is present. This contains the official Azure Policy definition schema used for validation.

5.  **Environment Variables (Optional/Future):**
    *   For the planned `deploy_policy_assignment` tool, Azure credentials will be required. It's recommended to configure these using environment variables recognized by `azure-identity` (e.g., `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`) or by using Managed Identity if deploying within Azure.
    *   `LOG_LEVEL`: Set to `INFO`, `DEBUG`, `WARNING`, or `ERROR` (uppercase) to control logging verbosity. Defaults might apply if not set.

## Running the Server

Use the `mcp` command-line tool to run the server in development mode:

```bash
mcp dev server.py
```

This will start the server and provide an interface (MCP Inspector) for testing the available tools.

## Usage

This server is intended to be used by an MCP client, typically integrated into an LLM application.

The general workflow for an LLM client would be:

1.  Use `get_builtin_policies` to find relevant policy categories.
2.  Use `get_policies_in_category` to list specific policies in a chosen category.
3.  Use `get_policy_content` to retrieve the JSON of example policies.
4.  Generate a custom policy based on user requirements and examples.
5.  *(Future)* Use `verify_policy_structure` to validate the generated JSON.
6.  *(Future)* Use `deploy_policy_assignment` to deploy the validated policy to Azure after confirming details with the user.

Using in Claude Desktop / VSCODE

```json
{
  "mcpServers": {
    "AzPolicy_mcp": {
      "command": "python",
      "args": [
        "PATH\\TO\\THE\\FILE\\server.py"
      ]
    }
  }
}
```

## Contributing

Please refer to the [`READMD.md`](./readme.md) for the current development plan and roadmap.

## License

MIT