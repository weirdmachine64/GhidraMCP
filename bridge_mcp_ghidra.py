# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, timeout: int, params: dict | None = None) -> list:
    """
    Perform a GET request with optional query parameters.
    
    Args:
        endpoint: The API endpoint to call
        timeout: Request timeout in seconds (mandatory)
        params: Optional query parameters
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, timeout: int, data: dict | str) -> str:
    """
    Perform a POST request with optional data.
    
    Args:
        endpoint: The API endpoint to call
        timeout: Request timeout in seconds (mandatory)
        data: Data to send in the request body
    """
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str, timeout: int) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", timeout, name)

@mcp.tool()
def rename_function(old_name: str, new_name: str, timeout: int) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", timeout, {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str, timeout: int) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", timeout, {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", timeout, {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str, timeout: int) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", timeout, {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str, timeout: int) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", timeout, {"address": address}))

@mcp.tool()
def get_current_address(timeout: int) -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address", timeout))

@mcp.tool()
def get_current_function(timeout: int) -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function", timeout))

@mcp.tool()
def list_functions(timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    List all functions in the database with pagination.
    """
    return safe_get("list_functions", timeout, {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function_by_address(address: str, timeout: int) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", timeout, {"address": address}))

@mcp.tool()
def disassemble_function(address: str, timeout: int) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", timeout, {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, timeout: int) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", timeout, {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str, timeout: int) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", timeout, {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, timeout: int) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", timeout, {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, timeout: int) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", timeout, {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, timeout: int) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", timeout, {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        timeout: Request timeout in seconds (mandatory)
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", timeout, {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        timeout: Request timeout in seconds (mandatory)
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", timeout, {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, timeout: int, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        timeout: Request timeout in seconds (mandatory)
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", timeout, {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(timeout: int, offset: int = 0, limit: int = 2000, filter: str | None = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        timeout: Request timeout in seconds (mandatory)
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params: dict[str, int | str] = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", timeout, params)

@mcp.tool()
def list_ghidra_mcp_tools(timeout: int) -> str:
    """
    List all available Ghidra MCP tools with their arguments and descriptions.
    
    Args:
        timeout: Request timeout in seconds (mandatory)
    
    Returns:
        Formatted string containing all available tools with their arguments and documentation
    """
    tools_info = [
        ("list_methods", "List all function names in the program with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of methods to return - optional, default: 100"),
        ]),
        ("list_classes", "List all namespace/class names in the program with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of classes to return - optional, default: 100"),
        ]),
        ("decompile_function", "Decompile a specific function by name and return the decompiled C code", [
            ("name (str)", "Function name to decompile - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("rename_function", "Rename a function by its current name to a new user-defined name", [
            ("old_name (str)", "Current function name - mandatory"),
            ("new_name (str)", "New function name - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("rename_data", "Rename a data label at the specified address", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("new_name (str)", "New label name - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("list_segments", "List all memory segments in the program with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of segments to return - optional, default: 100"),
        ]),
        ("list_imports", "List imported symbols in the program with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of imports to return - optional, default: 100"),
        ]),
        ("list_exports", "List exported functions/symbols with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of exports to return - optional, default: 100"),
        ]),
        ("list_namespaces", "List all non-global namespaces in the program with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of namespaces to return - optional, default: 100"),
        ]),
        ("list_data_items", "List defined data labels and their values with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of data items to return - optional, default: 100"),
        ]),
        ("search_functions_by_name", "Search for functions whose name contains the given substring", [
            ("query (str)", "Search query substring - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of results to return - optional, default: 100"),
        ]),
        ("rename_variable", "Rename a local variable within a function", [
            ("function_name (str)", "Function containing the variable - mandatory"),
            ("old_name (str)", "Current variable name - mandatory"),
            ("new_name (str)", "New variable name - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("get_function_by_address", "Get a function by its address", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("get_current_address", "Get the address currently selected by the user", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("get_current_function", "Get the function currently selected by the user", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("list_functions", "List all functions in the database with pagination", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Starting index for pagination - optional, default: 0"),
            ("limit (int)", "Maximum number of functions to return - optional, default: 100"),
        ]),
        ("decompile_function_by_address", "Decompile a function at the given address", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("disassemble_function", "Get assembly code (address: instruction; comment) for a function", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("set_decompiler_comment", "Set a comment for a given address in the function pseudocode", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("comment (str)", "Comment text - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("set_disassembly_comment", "Set a comment for a given address in the function disassembly", [
            ("address (str)", "Memory address in hex format - mandatory"),
            ("comment (str)", "Comment text - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("rename_function_by_address", "Rename a function by its address", [
            ("function_address (str)", "Memory address of function in hex format - mandatory"),
            ("new_name (str)", "New function name - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("set_function_prototype", "Set a function's prototype", [
            ("function_address (str)", "Memory address of function in hex format - mandatory"),
            ("prototype (str)", "Function prototype (C signature) - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("set_local_variable_type", "Set a local variable's type", [
            ("function_address (str)", "Memory address of containing function in hex format - mandatory"),
            ("variable_name (str)", "Variable name - mandatory"),
            ("new_type (str)", "New type (C type signature) - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
        ]),
        ("get_xrefs_to", "Get all references to the specified address (xref to)", [
            ("address (str)", "Target address in hex format (e.g. 0x1400010a0) - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Pagination offset - optional, default: 0"),
            ("limit (int)", "Maximum number of references to return - optional, default: 100"),
        ]),
        ("get_xrefs_from", "Get all references from the specified address (xref from)", [
            ("address (str)", "Source address in hex format (e.g. 0x1400010a0) - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Pagination offset - optional, default: 0"),
            ("limit (int)", "Maximum number of references to return - optional, default: 100"),
        ]),
        ("get_function_xrefs", "Get all references to the specified function by name", [
            ("name (str)", "Function name to search for - mandatory"),
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Pagination offset - optional, default: 0"),
            ("limit (int)", "Maximum number of references to return - optional, default: 100"),
        ]),
        ("list_strings", "List all defined strings in the program with their addresses", [
            ("timeout (int)", "Request timeout in seconds - mandatory"),
            ("offset (int)", "Pagination offset - optional, default: 0"),
            ("limit (int)", "Maximum number of strings to return - optional, default: 2000"),
            ("filter (str|None)", "Optional filter to match within string content - optional, default: None"),
        ]),
    ]
    
    result = "=== GHIDRA MCP TOOLS ===\n\n"
    for i, (tool_name, description, args) in enumerate(tools_info, 1):
        result += f"{i}. {tool_name}\n"
        result += f"   Description: {description}\n"
        result += "   Arguments:\n"
        for arg_name, arg_desc in args:
            result += f"      - {arg_name}: {arg_desc}\n"
        result += "\n"
    
    return result

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

