# Simple MCP Server starter with StdioServerTransport

This is a simple MCP server starter kit using the StdioServerTransport.

## Setup

Create a new MCP server with StdioServerTransport

PNPM
```
pnpm dlx github:akoskm/mcp-server-stdio my-mcp-server
```

NPM
```
npm create @akoskm/mcp-server-stdio my-mcp-server
```

This command will create a new directory called `my-mcp-server` with the contents of this repository.

Edit the `.cursor/mcp.json` file to change the runtime command if you are not using Bun.

Your MCP server will be picked up by Cursor automatically. If not, restart Cursor.

## Commands

### which app is running on port (mac only)
After this you can use the `which-app-on-port` tool to get the command and pid of the process running on a given port.

Example prompt in Cursor:

```
which app is running on port 9011?
```

### add two numbers
Example prompt in Cursor:
```
I have two open source projects and my friend has five, home many open source projects we have in total?
```
