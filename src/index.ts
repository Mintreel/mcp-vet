import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile } from "child_process";
// Create an MCP server
const server = new McpServer({
  name: "Demo",
  version: "1.0.0"
});

// Add an addition tool
server.tool("add",
  { a: z.number(), b: z.number() },
  async ({ a, b }) => ({
    content: [{ type: "text", text: String(a + b) }]
  })
);

interface ProcessInfo {
  command: string;
  pid: string | null;
}

server.tool("which-app-on-port", { port: z.number() }, async ({ port }) => {
  const result = await new Promise<ProcessInfo>((resolve, reject) => {
    execFile('lsof', ['-t', '-i', `tcp:${port}`], (error, pidStdout) => {
      if (error) {
        reject(error);
        return;
      }
      const pid = pidStdout.trim();
      execFile('ps', ['-o', 'comm=', '-p', pid], (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({ command: stdout.trim(), pid });
      });
    });
  });

  const response = {
    pid: result.pid,
    command: result.command,
  };

  return {
    content: [{ type: "text", text: JSON.stringify(response) }]
  };
});

// Add a dynamic greeting resource
server.resource(
  "greeting",
  new ResourceTemplate("greeting://{name}", { list: undefined }),
  async (uri, { name }) => ({
    contents: [{
      uri: uri.href,
      text: `Hello, ${name}!`
    }]
  })
);

// Start receiving messages on stdin and sending messages on stdout
const transport = new StdioServerTransport();
await server.connect(transport);

// output some info when the server is ready
console.error("MCP Server ready");