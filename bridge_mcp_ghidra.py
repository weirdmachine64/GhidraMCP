# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import asyncio
import sys
import requests
import argparse
import logging
from typing import Any
from urllib.parse import urljoin

import mcp.server.stdio
from mcp.server.lowlevel import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.types as types

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

# Create server instance
server = Server("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER


def safe_get(endpoint: str, timeout: int | None, params: dict | None = None) -> list:
    """
    Perform a GET request with optional query parameters.
    
    Args:
        endpoint: The API endpoint to call
        timeout: Request timeout in seconds (mandatory)
        params: Optional query parameters
    """
    if params is None:
        params = {}
    
    if timeout is None:
        timeout = 30

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


def safe_post(endpoint: str, timeout: int | None, data: dict | str | None) -> str:
    """
    Perform a POST request with optional data.
    
    Args:
        endpoint: The API endpoint to call
        timeout: Request timeout in seconds (mandatory)
        data: Data to send in the request body
    """
    if timeout is None:
        timeout = 30
    
    if data is None:
        data = ""
    
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8") if isinstance(data, str) else data, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def get_tool_definitions() -> list[types.Tool]:
    """Get all tool definitions for the MCP server."""
    return [
        types.Tool(
            name="list_methods",
            description="List all function names in the program with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of methods to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_classes",
            description="List all namespace/class names in the program with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of classes to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="decompile_function",
            description="Decompile a specific function by name and return the decompiled C code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Function name to decompile (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["name", "timeout"],
            },
        ),
        types.Tool(
            name="rename_function",
            description="Rename a function by its current name to a new user-defined name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "Current function name (mandatory)"},
                    "new_name": {"type": "string", "description": "New function name (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["old_name", "new_name", "timeout"],
            },
        ),
        types.Tool(
            name="rename_data",
            description="Rename a data label at the specified address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "new_name": {"type": "string", "description": "New label name (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "new_name", "timeout"],
            },
        ),
        types.Tool(
            name="list_segments",
            description="List all memory segments in the program with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of segments to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_imports",
            description="List imported symbols in the program with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of imports to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_exports",
            description="List exported functions/symbols with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of exports to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_namespaces",
            description="List all non-global namespaces in the program with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of namespaces to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_data_items",
            description="List defined data labels and their values with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of data items to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="search_functions_by_name",
            description="Search for functions whose name contains the given substring.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query substring (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of results to return", "default": 100},
                },
                "required": ["query", "timeout"],
            },
        ),
        types.Tool(
            name="rename_variable",
            description="Rename a local variable within a function.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Function containing the variable (mandatory)"},
                    "old_name": {"type": "string", "description": "Current variable name (mandatory)"},
                    "new_name": {"type": "string", "description": "New variable name (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["function_name", "old_name", "new_name", "timeout"],
            },
        ),
        types.Tool(
            name="get_function_by_address",
            description="Get a function by its address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "timeout"],
            },
        ),
        types.Tool(
            name="get_current_address",
            description="Get the address currently selected by the user.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="get_current_function",
            description="Get the function currently selected by the user.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_functions",
            description="List all functions in the database with pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Starting index for pagination", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of functions to return", "default": 100},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="decompile_function_by_address",
            description="Decompile a function at the given address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "timeout"],
            },
        ),
        types.Tool(
            name="disassemble_function",
            description="Get assembly code (address: instruction; comment) for a function.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "timeout"],
            },
        ),
        types.Tool(
            name="set_decompiler_comment",
            description="Set a comment for a given address in the function pseudocode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "comment": {"type": "string", "description": "Comment text (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "comment", "timeout"],
            },
        ),
        types.Tool(
            name="set_disassembly_comment",
            description="Set a comment for a given address in the function disassembly.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex format (mandatory)"},
                    "comment": {"type": "string", "description": "Comment text (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["address", "comment", "timeout"],
            },
        ),
        types.Tool(
            name="rename_function_by_address",
            description="Rename a function by its address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Memory address of function in hex format (mandatory)"},
                    "new_name": {"type": "string", "description": "New function name (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["function_address", "new_name", "timeout"],
            },
        ),
        types.Tool(
            name="set_function_prototype",
            description="Set a function's prototype.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Memory address of function in hex format (mandatory)"},
                    "prototype": {"type": "string", "description": "Function prototype (C signature) (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["function_address", "prototype", "timeout"],
            },
        ),
        types.Tool(
            name="set_local_variable_type",
            description="Set a local variable's type.",
            inputSchema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Memory address of containing function in hex format (mandatory)"},
                    "variable_name": {"type": "string", "description": "Variable name (mandatory)"},
                    "new_type": {"type": "string", "description": "New type (C type signature) (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["function_address", "variable_name", "new_type", "timeout"],
            },
        ),
        types.Tool(
            name="get_xrefs_to",
            description="Get all references to the specified address (xref to).",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Target address in hex format (e.g. 0x1400010a0) (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of references to return", "default": 100},
                },
                "required": ["address", "timeout"],
            },
        ),
        types.Tool(
            name="get_xrefs_from",
            description="Get all references from the specified address (xref from).",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Source address in hex format (e.g. 0x1400010a0) (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of references to return", "default": 100},
                },
                "required": ["address", "timeout"],
            },
        ),
        types.Tool(
            name="get_function_xrefs",
            description="Get all references to the specified function by name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Function name to search for (mandatory)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of references to return", "default": 100},
                },
                "required": ["name", "timeout"],
            },
        ),
        types.Tool(
            name="list_strings",
            description="List all defined strings in the program with their addresses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                    "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                    "limit": {"type": "integer", "description": "Maximum number of strings to return", "default": 2000},
                    "filter": {"type": ["string", "null"], "description": "Optional filter to match within string content", "default": None},
                },
                "required": ["timeout"],
            },
        ),
        types.Tool(
            name="list_ghidra_mcp_tools",
            description="List all available Ghidra MCP tools with their arguments and descriptions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timeout": {"type": "integer", "description": "Request timeout in seconds (mandatory)"},
                },
                "required": ["timeout"],
            },
        ),
    ]


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools."""
    return get_tool_definitions()


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Handle tool calls."""
    
    try:
        if name == "list_methods":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("methods", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_classes":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("classes", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "decompile_function":
            name_arg = arguments.get("name")
            timeout = arguments.get("timeout")
            result = safe_post("decompile", timeout, name_arg)
            return [types.TextContent(type="text", text=result)]
        
        elif name == "rename_function":
            old_name = arguments.get("old_name")
            new_name = arguments.get("new_name")
            timeout = arguments.get("timeout")
            result = safe_post("renameFunction", timeout, {"oldName": old_name, "newName": new_name})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "rename_data":
            address = arguments.get("address")
            new_name = arguments.get("new_name")
            timeout = arguments.get("timeout")
            result = safe_post("renameData", timeout, {"address": address, "newName": new_name})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "list_segments":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("segments", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_imports":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("imports", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_exports":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("exports", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_namespaces":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("namespaces", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_data_items":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("data", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "search_functions_by_name":
            query = arguments.get("query")
            timeout = arguments.get("timeout")
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            if not query:
                return [types.TextContent(type="text", text="Error: query string is required")]
            result = safe_get("searchFunctions", timeout, {"query": query, "offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "rename_variable":
            function_name = arguments.get("function_name")
            old_name = arguments.get("old_name")
            new_name = arguments.get("new_name")
            timeout = arguments.get("timeout")
            result = safe_post("renameVariable", timeout, {
                "functionName": function_name,
                "oldName": old_name,
                "newName": new_name
            })
            return [types.TextContent(type="text", text=result)]
        
        elif name == "get_function_by_address":
            address = arguments.get("address")
            timeout = arguments.get("timeout")
            result = safe_get("get_function_by_address", timeout, {"address": address})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "get_current_address":
            timeout = arguments.get("timeout")
            result = safe_get("get_current_address", timeout)
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "get_current_function":
            timeout = arguments.get("timeout")
            result = safe_get("get_current_function", timeout)
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_functions":
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            timeout = arguments.get("timeout")
            result = safe_get("list_functions", timeout, {"offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "decompile_function_by_address":
            address = arguments.get("address")
            timeout = arguments.get("timeout")
            result = safe_get("decompile_function", timeout, {"address": address})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "disassemble_function":
            address = arguments.get("address")
            timeout = arguments.get("timeout")
            result = safe_get("disassemble_function", timeout, {"address": address})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "set_decompiler_comment":
            address = arguments.get("address")
            comment = arguments.get("comment")
            timeout = arguments.get("timeout")
            result = safe_post("set_decompiler_comment", timeout, {"address": address, "comment": comment})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "set_disassembly_comment":
            address = arguments.get("address")
            comment = arguments.get("comment")
            timeout = arguments.get("timeout")
            result = safe_post("set_disassembly_comment", timeout, {"address": address, "comment": comment})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "rename_function_by_address":
            function_address = arguments.get("function_address")
            new_name = arguments.get("new_name")
            timeout = arguments.get("timeout")
            result = safe_post("rename_function_by_address", timeout, {"function_address": function_address, "new_name": new_name})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "set_function_prototype":
            function_address = arguments.get("function_address")
            prototype = arguments.get("prototype")
            timeout = arguments.get("timeout")
            result = safe_post("set_function_prototype", timeout, {"function_address": function_address, "prototype": prototype})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "set_local_variable_type":
            function_address = arguments.get("function_address")
            variable_name = arguments.get("variable_name")
            new_type = arguments.get("new_type")
            timeout = arguments.get("timeout")
            result = safe_post("set_local_variable_type", timeout, {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})
            return [types.TextContent(type="text", text=result)]
        
        elif name == "get_xrefs_to":
            address = arguments.get("address")
            timeout = arguments.get("timeout")
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            result = safe_get("xrefs_to", timeout, {"address": address, "offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "get_xrefs_from":
            address = arguments.get("address")
            timeout = arguments.get("timeout")
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            result = safe_get("xrefs_from", timeout, {"address": address, "offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "get_function_xrefs":
            name_arg = arguments.get("name")
            timeout = arguments.get("timeout")
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 100)
            result = safe_get("function_xrefs", timeout, {"name": name_arg, "offset": offset, "limit": limit})
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_strings":
            timeout = arguments.get("timeout")
            offset = arguments.get("offset", 0)
            limit = arguments.get("limit", 2000)
            filter_arg = arguments.get("filter")
            params: dict[str, int | str] = {"offset": offset, "limit": limit}
            if filter_arg:
                params["filter"] = filter_arg
            result = safe_get("strings", timeout, params)
            return [types.TextContent(type="text", text="\n".join(result))]
        
        elif name == "list_ghidra_mcp_tools":
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
            
            return [types.TextContent(type="text", text=result)]
        
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error executing tool: {str(e)}")]


async def run_server(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8081) -> None:
    """Run the MCP server with the specified transport."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="ghidra-mcp",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
    logger.info(f"Using transport: {args.transport}")
    
    if args.transport == "stdio":
        try:
            asyncio.run(run_server("stdio"))
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        logger.error("SSE transport not yet implemented with low-level API")
        sys.exit(1)


if __name__ == "__main__":
    main()
