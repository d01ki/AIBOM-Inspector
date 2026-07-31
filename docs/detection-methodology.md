# Detection methodology

## Evidence contract

Every reported entity is tied to source evidence. AST evidence includes the
detector ID, source kind, line/column span, a bounded snippet, and confidence.
No target code is imported, evaluated, or executed.

## Python analysis

The parser indexes imports and aliases, assignments by scope, parent nodes,
function calls, docstring spans, and known entrypoints. Provider detectors then
identify actual constructor/API calls rather than model-like strings alone.

The bounded value resolver supports:

- scalar string constants and variable references;
- dictionaries, lists, tuples, subscripts, and `dict.get`;
- static string concatenation and fully static f-strings;
- `os.getenv`/`os.environ.get` defaults;
- unresolved `os.environ[...]` references without exposing a secret value;
- one-hop wrapper-function argument tracing.

Unknown expressions remain `unresolved`; they are never converted into guessed
model names. Resolution steps are serialized so users can audit how a value was
derived.

## TypeScript / JavaScript analysis

JS/TS is parsed by `aibom.detectors.javascript`, a dependency-free tolerant
recursive-descent parser. There is no Node.js runtime, no `npm install` of the
target, no bundling, and no transpilation — the scanner reads text, exactly as
it does for Python.

The parser models only what the analysis needs: import bindings, `require()`,
variable and property bindings by scope, call and member expressions, object and
array literals, template literals (including nested `${…}`), and function bodies
including arrow functions. TypeScript type syntax — annotations, generics,
`interface`/`type`/`enum`/`declare`, `as`/`satisfies`, non-null assertions,
parameter modifiers, and decorators — is skipped rather than represented.

Tolerance is a contract, not an accident: unfamiliar or invalid syntax degrades
to an `Unknown` node and the parser resynchronizes at the next statement, so one
odd file cannot abort a repository scan. Bracket nesting is capped so a
pathological input cannot exhaust the stack.

The index it produces mirrors the Python one — import aliases (resolving npm
scopes and `node:` prefixes), scoped bindings, call sites, and entrypoint
classification. Entrypoints are recognized from framework-named exports
(`export async function POST`), router registrations (`app.post(path, handler)`),
and tool registrars (`server.tool(name, schema, handler)`).

`javascript.prompt-flow.ast` then applies the same reasoning as its Python
counterpart:

| Stage | TypeScript surface |
|---|---|
| Prompt sinks | `generateText`/`streamText`/`generateObject`/`streamObject` (`ai`), `new Agent({instructions})` (`@openai/agents`), `chat.completions.create`, `responses.create`, `beta.assistants.create`, `messages.create`/`messages.stream` |
| Roles | `system`/`prompt` options and `messages[].role` are separated; only `system`/`developer` count as privileged |
| Sources | route-handler parameters, `request.json()`/`text()`/`formData()`, `req.body`/`query`/`params`/`headers`, `searchParams.get`, MCP tool parameters, `process.argv`/`env`, `fs` reads, retrieval and database calls |
| Bindings | `tools: { name: tool({ execute }) }` (object map) and `tools: [boundTool]` (array), resolved through variable bindings |
| Operations | `child_process`, `fs`/`fs/promises` writes and deletes, `eval`/`new Function`/`vm`, state-changing `fetch`/`axios`, mailer sends |

The same restrictions apply as in Python: the operation must sit inside an
explicitly bound tool's executor, and at least one of that executor's parameters
must be proven to influence the call. A fixed command, an unbound helper, or a
merely co-located dangerous call is not promoted to a capability.

## Prompt source-to-sink analysis

The `python.prompt-flow.ast` detector recognizes privileged and user prompt
arguments in OpenAI Responses, Chat Completions, Completions, and Assistants,
plus Anthropic Messages and Completions. Direct message lists are split by role
so untrusted user content does not taint an independent static system message.

The bounded tracer follows same-file assignments, concatenation, f-strings,
containers, subscripts, and wrapper-call arguments. Recognized sources include
HTTP request/route parameters, CLI input, environment variables, WebSocket
messages, files, retrieved documents, and database results. Each prompt records
the source kind, sink kind, trust boundary, model reference, and sanitized flow
steps. Prompt text is never written to evidence or flow paths; statically
resolved content is represented only by a SHA-256-derived hash.

`AIBOM-PROMPT-004` fires only when a proven untrusted path reaches a system or
developer instruction. Unknown paths remain explicit and do not become a
security claim.

Confirmed user-controlled paths are also projected into `ExposurePath`
artifacts. The path contains only source/sink identifiers, trust-boundary
metadata, model references, reachability, sanitized operations, and evidence.
Static prompt text is never copied. `aibom diff` compares these paths across
revisions; a safe static system instruction becoming user-controlled is
reported even when the model and dependency inventories do not change.

## Agent capability blast radius

For an OpenAI Agents SDK `Agent(...)` call, the detector reads
`instructions=`, `model=`, and an explicit `tools=[...]` list.

The recognized construction follows the official
[Agents](https://openai.github.io/openai-agents-python/agents/) and
[function tools](https://openai.github.io/openai-agents-python/tools/)
interfaces; repository code is parsed but the SDK is never imported.

A potential impact path is produced only when all of the following are proven
in one bounded analysis:

1. untrusted input reaches system-level `instructions`;
2. the same constructor directly binds the named tool;
3. the function has a recognized tool decorator such as `@function_tool`;
4. a tool parameter reaches a recognized operation, including command
   execution, filesystem mutation, network egress, or an external action; and
5. the agent constructor is not classified as unreachable.

This intentionally rejects same-file co-location, unbound dangerous helpers,
undecorated functions, and fixed operations such as
`subprocess.run(["uptime"])`. Evidence stores the binding, parameter name,
sanitized qualified operation, and line—not argument values.

`AIBOM-IMPACT-001` is emitted instead of the generic prompt-exposure finding
for the same root path, avoiding duplicate score deductions. `aibom diff`
compares stable prompt anchors and capability signatures; it emits
`impact_path_added` when a revision creates the connected blast radius while
the component set remains unchanged.

## Usage classification

The states are intentionally independent:

```text
declared -> imported -> instantiated -> invoked -> reachable
                                      runtime_observed (independent evidence)
```

An SDK import creates an imported service, not an invoked model. An API call
with a model argument creates an invoked model. Manifest packages are declared
only. Runtime evidence is not yet ingested and therefore remains false.

## Reachability

The initial call graph is same-file and bounded. It recognizes FastAPI/Flask-
style routes, router routes, CLI command decorators, task/tool decorators,
common Lambda handler names, and `if __name__ == "__main__"` calls. Results are:

- `true`: a static path from a supported entrypoint was found;
- `false`: supported entrypoints exist in the file, but no same-file path was found;
- `unknown`: there is no supported entrypoint or analysis is insufficient.

`false` must not be interpreted as globally unreachable until cross-file and
dynamic dispatch analysis are implemented.

## Confidence

Confidence is separated into syntax, value resolution, framework identity,
reachability, and runtime confirmation. AST-confirmed calls receive high syntax
confidence; unresolved values and regex-only matches stay lower. The original
evidence confidence remains available for existing filters.

## Precision controls

For valid Python source, comments and docstrings are removed before legacy
matching and model-like unused constants are not inventory components. Test,
fixture, example, demo, and docs paths are tagged so downstream policy can
filter them without discarding their evidence.

Security configuration signals in valid Python use AST nodes rather than line
regexes. `trust_remote_code=True` must be an actual boolean call keyword, and a
hardcoded secret must be an actual literal assignment or keyword value.
Detector regex definitions, finding descriptions, and source-code strings used
by unit tests are therefore not interpreted as runtime configuration.

The default risk policy evaluates production-context entities and signals.
Test/example/docs components remain in the inventory and CycloneDX output, but
are excluded from findings, score, dependency graph, exposure paths, and impact
paths. Scanning a fixture directory as the target makes its relative source
files production scope, preserving the built-in demos and focused fixture
analysis.
