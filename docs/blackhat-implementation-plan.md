# AIBOM Inspector 改善・実装計画書
## Black Hat Arsenal 採択と外部リポジトリ検出精度向上のための実装仕様

対象リポジトリ: `https://github.com/d01ki/AIBOM-Inspector`

---

# 1. 目的

AIBOM Inspectorを、単なるAIコンポーネント検出ツールではなく、以下を満たす実運用可能なAIアプリケーション向けセキュリティ解析ツールへ改善する。

1. 自身のテスト用リポジトリ以外でも高い検出精度を出す
2. 誤検知を減らし、検出根拠を説明できるようにする
3. AIモデル、プロンプト、エージェント、MCP、外部AIサービスの関係性を可視化する
4. 実際に本番コードから到達可能なAIコンポーネントを判定する
5. Black Hat Arsenal審査で「新規性」「実用性」「再現性」を説明できる状態にする
6. CI/CDやPull Requestレビューに組み込めるようにする

---

# 2. 現状の主要課題

## 2.1 外部リポジトリで検出精度が落ちる

現在の検出方式が主に正規表現、文字列検索、行単位のパターンマッチに依存している場合、以下を取りこぼしやすい。

```python
MODEL_NAME = os.environ["MODEL_NAME"]
client.responses.create(model=MODEL_NAME)
```

```python
config = load_config()
pipeline(model=config.inference.model)
```

```python
MODEL = "meta-llama/" + variant
```

```typescript
const client = createClient(providerConfig);
await client.chat({ model: settings.model });
```

実際のリポジトリでは、モデル名、APIエンドポイント、プロンプト、MCP設定などは別ファイル、環境変数、設定オブジェクト、ラッパー関数を経由することが多い。

## 2.2 宣言されている依存関係と実際に使われる依存関係を区別できていない

依存パッケージが存在しても、実際には以下の可能性がある。

- 開発依存
- テスト専用
- サンプルコード専用
- 未使用
- 廃止コード
- 推移的依存
- 本番経路から到達不能

単にマニフェストに存在するだけで重要コンポーネントと判断すると、ノイズが増える。

## 2.3 実リポジトリに対する評価データが不足している

合成fixtureのみでは、Black Hat審査や実利用者に対して精度を証明しにくい。

必要なのは以下。

- 公開リポジトリを用いた評価
- 手動で作成した正解データ
- Precision
- Recall
- F1
- カテゴリ別評価
- 誤検知と取りこぼしの一覧
- 再現可能なベンチマーク手順

## 2.4 検出結果に到達可能性がない

「存在する」だけではセキュリティ上の重要度が分からない。

必要な判定例:

```text
Declared: Yes
Imported: Yes
Instantiated: Yes
Invoked: Yes
Reachable from production entrypoint: Yes
Observed at runtime: No
```

## 2.5 プロンプト、MCP、エージェントの検出が在庫管理に留まっている

Black Hat向けには、単なる列挙ではなく、攻撃面を示す必要がある。

例:

```text
User Input
  -> Prompt Template
    -> LLM
      -> MCP Tool
        -> Shell Execution
```

---

# 3. 最終的なプロダクト定義

AIBOM Inspectorを以下のように定義する。

> AIBOM Inspector is an evidence-backed attack-surface analyzer for AI applications. It discovers models, prompts, agents, datasets, external AI services, and LLM-invokable tools, then maps how they are connected and which components are reachable from production entry points.

日本語:

> AIBOM Inspectorは、AIアプリケーション内のモデル、プロンプト、エージェント、データセット、外部AIサービス、LLMから呼び出し可能なツールを検出し、ソースコード上の根拠と到達可能性を示すAI攻撃面解析ツールである。

---

# 4. 実装優先順位

## 優先度S

1. 実リポジトリ評価ハーネス
2. AST解析
3. 軽量な値解決
4. 検出根拠とConfidenceの改善
5. Reachability Analysis

## 優先度A

6. 設定ファイルとコードのクロスファイル解決
7. Prompt Source-to-Sink解析
8. MCP Capability解析
9. `aibom diff`
10. SARIF出力
11. Policy as Code
12. GitHub Actions統合

## 優先度B

13. ランタイム証拠の取り込み
14. Plugin SDK
15. JavaScript/TypeScript解析強化
16. Terraform、Kubernetes、Helm解析
17. AIサプライチェーン真正性確認

---

# 5. Phase 1: 実リポジトリ評価ハーネス

## 5.1 目的

実装変更前後で検出精度を比較できるようにする。

## 5.2 推奨ディレクトリ構成

```text
benchmark/
├── README.md
├── repos.yaml
├── evaluate.py
├── schemas/
│   └── ground-truth.schema.json
├── ground_truth/
│   ├── langchain.json
│   ├── llama_index.json
│   ├── open_webui.json
│   ├── autogen.json
│   ├── crewai.json
│   └── negative_python_app.json
├── snapshots/
│   └── expected-results/
└── reports/
    ├── latest.json
    └── latest.md
```

## 5.3 評価対象候補

最低20件、可能なら30から50件。

### AIフレームワーク

- LangChain
- LangGraph
- LlamaIndex
- AutoGen
- CrewAI
- Haystack
- LiteLLM
- OpenAI SDK利用アプリ
- Anthropic SDK利用アプリ
- Hugging Face Transformers
- Diffusers
- Ollama
- vLLM
- Open WebUI
- MCP server
- FastAPI + LLM
- Flask + LLM
- AI CLIアプリ
- RAGアプリ
- Agentアプリ

### 負例

- 通常のPython Webアプリ
- 通常のNode.jsアプリ
- AIに関するREADMEのみを含むリポジトリ
- AIパッケージを開発依存にだけ含むリポジトリ
- テストコード内にだけOpenAI文字列を含むリポジトリ

## 5.4 Ground Truth形式

```json
{
  "repository": "owner/repo",
  "commit": "full-commit-sha",
  "components": [
    {
      "type": "model",
      "name": "gpt-4.1",
      "file": "src/service.py",
      "line": 31,
      "status": "invoked"
    }
  ]
}
```

## 5.5 評価指標

カテゴリ別に算出する。

- Models
- AI Services
- Prompts
- Agents
- Tools
- MCP
- Datasets
- Model Files
- AI Packages

出力例:

```text
Models:
  Precision: 0.94
  Recall:    0.81
  F1:        0.87

Services:
  Precision: 0.97
  Recall:    0.90
  F1:        0.93
```

## 5.6 受け入れ条件

- `python benchmark/evaluate.py` で評価可能
- JSONとMarkdownで結果を生成
- 検出漏れ一覧を出力
- 誤検知一覧を出力
- CIで評価可能
- ベンチマーク対象コミットを固定
- 最新スコアをREADMEに掲載可能

---

# 6. Phase 2: Detectorアーキテクチャ分割

## 6.1 目的

巨大な単一Collectorから、言語別、フレームワーク別、責務別のDetector構成へ分割する。

## 6.2 推奨構成

```text
src/aibom/
├── detectors/
│   ├── base.py
│   ├── registry.py
│   ├── result.py
│   ├── python/
│   │   ├── parser.py
│   │   ├── value_resolver.py
│   │   ├── call_graph.py
│   │   ├── imports.py
│   │   ├── openai.py
│   │   ├── anthropic.py
│   │   ├── huggingface.py
│   │   ├── langchain.py
│   │   ├── langgraph.py
│   │   ├── llamaindex.py
│   │   └── mcp.py
│   ├── javascript/
│   │   ├── parser.py
│   │   ├── value_resolver.py
│   │   ├── openai.py
│   │   ├── anthropic.py
│   │   └── mcp.py
│   ├── config/
│   │   ├── dotenv.py
│   │   ├── yaml.py
│   │   ├── json.py
│   │   ├── toml.py
│   │   ├── docker.py
│   │   ├── kubernetes.py
│   │   └── github_actions.py
│   └── generic/
│       ├── model_urls.py
│       ├── model_files.py
│       ├── prompt_files.py
│       └── ai_packages.py
```

## 6.3 共通インターフェース

```python
from dataclasses import dataclass, field
from typing import Iterable, Protocol

@dataclass
class Evidence:
    file: str
    line: int | None
    column: int | None
    snippet: str | None
    kind: str

@dataclass
class ResolutionStep:
    file: str
    line: int | None
    symbol: str | None
    value: str | None
    operation: str

@dataclass
class Detection:
    entity_type: str
    name: str
    detector_id: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    resolution_path: list[ResolutionStep] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

class Detector(Protocol):
    detector_id: str

    def supports(self, path: str) -> bool:
        ...

    def detect(self, context: "ScanContext") -> Iterable[Detection]:
        ...
```

## 6.4 受け入れ条件

- 既存検出機能を壊さない
- 各Detectorが独立テスト可能
- Detector IDを出力へ含める
- Detector単位で無効化可能
- Plugin追加を将来的に可能にする
- 同一対象の重複検出をマージする

---

# 7. Phase 3: Python AST解析

## 7.1 目的

文字列検索ではなく、Python構文を理解して検出する。

## 7.2 対応する構文

- Import
- ImportFrom
- Assign
- AnnAssign
- Constant
- Name
- Attribute
- Call
- Dict
- List
- Tuple
- JoinedStr
- BinOp
- Subscript
- FunctionDef
- AsyncFunctionDef
- ClassDef
- Return
- If
- With
- AsyncWith

## 7.3 最初に対応する値解決

### 文字列定数

```python
MODEL = "gpt-4.1"
```

### 単純な変数参照

```python
MODEL = "gpt-4.1"
client.responses.create(model=MODEL)
```

### 辞書

```python
CONFIG = {"model": "gpt-4.1"}
client.responses.create(model=CONFIG["model"])
```

### f-stringの静的部分

```python
MODEL = f"gpt-{VERSION}"
```

VERSIONも静的に解決可能なら完全解決する。

### 文字列結合

```python
MODEL = "meta-llama/" + "Llama-3.1-8B"
```

### 環境変数

```python
MODEL = os.getenv("MODEL_NAME", "gpt-4.1")
```

結果:

```json
{
  "resolved_value": "gpt-4.1",
  "resolution_kind": "environment_default",
  "environment_variable": "MODEL_NAME"
}
```

### 関数引数の簡易追跡

```python
def create_client(model):
    return OpenAIModel(model=model)

create_client("gpt-4.1")
```

## 7.4 import alias対応

```python
from openai import OpenAI as OA
client = OA()
```

```python
import openai as ai
ai.OpenAI()
```

## 7.5 受け入れ条件

- 既存RegexよりRecallが向上
- コメント内文字列を検出しない
- docstring内サンプルをデフォルトでは検出しない
- importだけで「使用中」と判断しない
- API呼び出し引数の値を解決できる
- 解決経路を出力できる
- AST parse失敗時はRegex fallback可能

---

# 8. Phase 4: JavaScript/TypeScript解析

## 8.1 推奨方式

Tree-sitter、TypeScript Compiler API、またはBabel Parserを利用する。

候補:

- `tree-sitter`
- `tree-sitter-javascript`
- `tree-sitter-typescript`

## 8.2 対応対象

```typescript
const model = "gpt-4.1";
client.responses.create({ model });
```

```typescript
const config = {
  model: "claude-sonnet-4"
};
client.messages.create({ model: config.model });
```

```typescript
const client = new OpenAI({
  baseURL: process.env.OPENAI_BASE_URL
});
```

## 8.3 受け入れ条件

- `.js`
- `.jsx`
- `.ts`
- `.tsx`
- ESM import
- CommonJS require
- alias import
- object property
- environment variable
- wrapper関数

---

# 9. Phase 5: 使用状態の分類

## 9.1 目的

依存関係、import、生成、呼び出し、到達可能性を区別する。

## 9.2 ステータス

```text
declared
imported
instantiated
invoked
reachable
runtime_observed
```

## 9.3 出力例

```json
{
  "name": "langchain",
  "type": "framework",
  "usage": {
    "declared": true,
    "imported": true,
    "instantiated": true,
    "invoked": true,
    "reachable": false,
    "runtime_observed": false
  }
}
```

## 9.4 受け入れ条件

- マニフェストだけの依存を低優先度にする
- テストコード内だけの場合に識別する
- サンプル、examples、docs配下を識別する
- 本番コードと開発コードを区別する
- UI上でフィルタ可能にする

---

# 10. Phase 6: クロスファイル設定値解決

## 10.1 対応ファイル

- `.env`
- `.env.example`
- YAML
- JSON
- TOML
- Docker Compose
- Kubernetes ConfigMap
- Kubernetes Secret参照
- Helm values
- GitHub Actions
- Terraform variables

## 10.2 例

```yaml
providers:
  primary:
    type: openai
    model: gpt-4.1
    base_url: https://api.openai.com/v1
```

```python
provider = create_provider(config["providers"]["primary"])
```

期待する関係:

```text
config.yaml:model
  -> config loader
    -> provider factory
      -> OpenAI client
        -> gpt-4.1
```

## 10.3 解決グラフ

内部で以下を管理する。

```python
@dataclass
class SymbolReference:
    source_file: str
    source_path: str
    target_file: str
    target_symbol: str
    value: object
```

## 10.4 受け入れ条件

- YAML/JSON/TOMLのキーをソースコード参照と結びつける
- 環境変数名を記録する
- 秘密値そのものは出力しない
- デフォルト値のみ安全に表示する
- 不明値は`unresolved`として保持する
- 推測で確定値にしない

---

# 11. Phase 7: Reachability Analysis

## 11.1 目的

本番入口からAIコンポーネントまで到達可能か判定する。

## 11.2 初期対応するEntry Point

### Python

- FastAPI route
- Flask route
- Django view
- CLI entry point
- AWS Lambda handler
- Azure Functions
- Google Cloud Functions
- Celery task
- LangGraph node
- MCP tool handler
- `if __name__ == "__main__"`

### JavaScript/TypeScript

- Express route
- Next.js API route
- Next.js Server Action
- AWS Lambda handler
- Cloudflare Worker
- CLI command
- MCP tool handler

## 11.3 Call Graph

最初は軽量でよい。

- 同一ファイル関数呼び出し
- import先関数呼び出し
- クラスメソッド呼び出し
- 最大深度を設定
- dynamic dispatchは`unknown`
- decoratorからroute情報を取得

## 11.4 出力例

```json
{
  "entrypoint": {
    "file": "app.py",
    "line": 20,
    "type": "fastapi_route",
    "name": "POST /chat"
  },
  "target": {
    "type": "model",
    "name": "gpt-4.1"
  },
  "reachable": true,
  "path": [
    "app.chat",
    "service.answer",
    "agent.invoke",
    "openai.responses.create"
  ],
  "confidence": 0.83
}
```

## 11.5 UI表示

```text
POST /chat
  -> answer()
    -> agent.invoke()
      -> gpt-4.1
        -> MCP: execute_shell
```

## 11.6 受け入れ条件

- entrypointを一覧化
- entrypointから対象までの経路表示
- 到達不能な依存を区別
- 最大探索深度を設定可能
- 解析不能はfalseではなくunknown
- Call Graphの根拠をfile:lineで表示

---

# 12. Phase 8: Prompt Source-to-Sink解析

## 12.1 Source候補

- HTTP request body
- HTTP query parameter
- HTTP path parameter
- CLI argument
- Environment variable
- WebSocket message
- Retrieved document
- Database value
- File content
- Tool output
- MCP tool result

## 12.2 Sink候補

- system prompt
- developer prompt
- user message
- prompt template
- LLM API call
- Agent invoke
- Tool selection prompt
- RAG context

## 12.3 検出ルール候補

- ユーザー入力をsystem promptへ直接連結
- 未信頼入力をinstruction領域へ挿入
- Web取得結果を無加工でLLMへ送信
- RAG文書を命令として扱う
- Tool outputを次のLLM入力へ直接渡す
- Prompt内に秘密情報
- Prompt内に内部URL
- Guardrail前に外部入力が入る
- Prompt template変数が未検証

## 12.4 例

```python
system_prompt = BASE_PROMPT + request.user_input
client.responses.create(
    model="gpt-4.1",
    input=system_prompt
)
```

結果:

```text
AIBOM-PROMPT-004

Untrusted input is concatenated into a system-level instruction.

Source:
  app.py:48 request.user_input

Sink:
  app.py:51 responses.create.input

Path:
  request.user_input
    -> system_prompt
      -> responses.create()
```

## 12.5 受け入れ条件

- SourceとSinkを別々に識別
- データフローパスを表示
- file:lineを出力
- 信頼境界を表現
- 誤検知抑制のためConfidenceを付与
- `unknown`パスを扱う

---

# 13. Phase 9: MCP Capability解析

## 13.1 Capability分類

```text
filesystem.read
filesystem.write
process.execute
network.egress
credential.access
database.query
cloud.control
browser.control
email.send
calendar.write
code.execute
package.install
```

## 13.2 解析対象

- MCP server定義
- MCP client設定
- tool decorator
- JSON schema
- command execution
- filesystem操作
- HTTP request
- subprocess
- shell
- database client
- cloud SDK
- browser automation
- 認証情報アクセス

## 13.3 検出ルール候補

- shell実行可能
- 任意コマンド実行
- 任意パス読み取り
- 任意パス書き込み
- SSRF可能なURL入力
- credential参照
- allowlistなし
- ユーザー確認なし
- 引数スキーマが過度に自由
- tool説明と実装権限の不一致
- 外部インターフェースへbind
- 認証なし
- LLMから直接呼び出し可能

## 13.4 出力例

```json
{
  "tool": "run_command",
  "server": "local-admin-mcp",
  "capabilities": [
    "process.execute",
    "network.egress"
  ],
  "user_confirmation": false,
  "allowlist": false,
  "reachable_from_model": true,
  "risk": "critical"
}
```

## 13.5 受け入れ条件

- MCP serverとtoolを分けて表示
- toolごとのCapabilityを表示
- LLMからの到達可能性を表示
- 危険操作にルールIDを付与
- MCP GraphをHTMLで可視化

---

# 14. Phase 10: Confidenceモデル

## 14.1 目的

単一のconfidenceではなく、根拠ごとに評価する。

## 14.2 推奨形式

```json
{
  "confidence": 0.91,
  "confidence_factors": {
    "syntax_confidence": 1.0,
    "value_resolution_confidence": 0.9,
    "framework_identification_confidence": 1.0,
    "reachability_confidence": 0.7,
    "runtime_confirmation": 0.0
  }
}
```

## 14.3 Confidenceレベル

```text
Confirmed:
  AST + value resolution
  またはruntime evidenceあり

High:
  ASTでAPI呼び出しを確認

Medium:
  importまたは設定値まで確認

Low:
  テキスト、URL、ファイル名のみ
```

## 14.4 受け入れ条件

- UIでLow Confidenceを非表示可能
- Confidence算出根拠を表示
- Detectorごとに重みを設定可能
- Regexだけの検出をHighにしない
- Runtime確認済みを明示

---

# 15. Phase 11: `aibom diff`

## 15.1 目的

Pull Requestやリリース間でAIサプライチェーンの変更を検出する。

## 15.2 CLI

```bash
aibom diff before.json after.json
```

または:

```bash
aibom diff \
  --base-ref origin/main \
  --head-ref HEAD
```

## 15.3 出力例

```text
+ Added model: unknown-user/llama-3-finetune
+ Added trust_remote_code=True
+ Added MCP tool: execute_shell
- Removed pinned revision: 8f23c19
Risk score: 54 -> 86
```

## 15.4 JSON形式

```json
{
  "added": [],
  "removed": [],
  "changed": [],
  "risk_score_before": 54,
  "risk_score_after": 86
}
```

## 15.5 受け入れ条件

- コンポーネント追加/削除
- リスク追加/削除
- Confidence変化
- Reachability変化
- ライセンス変化
- モデルrevision変化
- CLI、JSON、Markdown出力
- PRコメントに利用可能

---

# 16. Phase 12: SARIF出力

## 16.1 CLI

```bash
aibom scan . --sarif aibom.sarif
```

## 16.2 SARIFへ含めるもの

- ruleId
- severity
- message
- file
- line
- column
- help text
- remediation
- related location
- code flow
- partial fingerprints

## 16.3 受け入れ条件

- GitHub Code Scanningで読める
- 同一Findingを重複登録しない
- Code Flowを表示
- ルール説明URLを持つ
- SARIF schema validationを通過

---

# 17. Phase 13: Policy as Code

## 17.1 例

```yaml
version: 1

policies:
  - id: deny-trust-remote-code
    action: deny
    when:
      finding_rule: trust_remote_code

  - id: require-model-revision
    action: require
    when:
      component_type: model
    condition:
      revision_pinned: true

  - id: deny-unknown-license
    action: deny
    when:
      component_type: model
      license:
        - unknown
        - non-commercial

  - id: confirm-dangerous-tools
    action: require
    when:
      capability:
        - process.execute
        - filesystem.write
    condition:
      user_confirmation: true
```

## 17.2 CLI

```bash
aibom scan . --policy organization-policy.yaml
```

## 17.3 受け入れ条件

- deny
- warn
- require
- severity override
- exit code制御
- policy結果をJSON/HTML/SARIFへ反映
- schema validation

---

# 18. Phase 14: ランタイム証拠

## 18.1 目的

静的解析結果に実行時情報を重ねる。

## 18.2 初期対応

汎用JSONインポートから開始する。

```bash
aibom scan . \
  --runtime-evidence runtime.json
```

## 18.3 Runtime Evidence形式

```json
{
  "observations": [
    {
      "type": "model_call",
      "provider": "openai",
      "model": "gpt-4.1",
      "count": 18432,
      "first_seen": "2026-07-01T00:00:00Z",
      "last_seen": "2026-07-13T18:10:00Z"
    }
  ]
}
```

## 18.4 将来対応

- OpenTelemetry
- Falco
- eBPF
- Kubernetes Audit Log
- CloudTrail
- API Gateway
- LiteLLM log
- OpenAI log
- Anthropic log
- MCP audit log

## 18.5 受け入れ条件

- 静的コンポーネントとruntime observationをマージ
- 観測回数
- first seen
- last seen
- 本番利用有無
- 未観測と未到達を区別

---

# 19. Phase 15: AIサプライチェーン真正性

## 19.1 追加チェック

- Hugging Face revision固定
- commit SHA固定
- モデルファイルSHA-256
- Git LFS pointer
- OCI digest
- Sigstore署名
- SLSA provenance
- 作者組織
- custom codeファイル
- `trust_remote_code=True`
- pickle形式
- safetensors利用有無
- model card
- license
- gated model
- 同名モデル
- 不審なダウンロードドメイン

## 19.2 受け入れ条件

- ネットワーク無効時も基本スキャン可能
- Resolver有効時のみ外部照会
- 外部照会結果をキャッシュ
- 取得元URLを記録
- 署名、digest、revisionを区別

---

# 20. CLI改善

## 20.1 推奨コマンド

```bash
aibom scan .
aibom scan . --format json
aibom scan . --format cyclonedx
aibom scan . --html report.html
aibom scan . --sarif report.sarif
aibom scan . --policy policy.yaml
aibom scan . --fail-on high
aibom scan . --confidence high
aibom scan . --reachability
aibom scan . --runtime-evidence runtime.json
aibom diff before.json after.json
aibom benchmark
aibom rules list
aibom rules show AIBOM-PROMPT-004
```

## 20.2 受け入れ条件

- exit codeを文書化
- CI向けquiet mode
- JSON Lines
- progress無効化
- offline mode
- cache directory指定
- max file size
- exclude pattern
- include pattern
- language selection

---

# 21. HTMLレポート改善

## 21.1 必須ビュー

- Executive Summary
- AI Inventory
- Attack Surface Graph
- Reachability
- Prompt Data Flow
- MCP Capability
- Findings
- Evidence
- Diff
- Runtime Observations
- Policy Results
- Limitations

## 21.2 フィルタ

- component type
- severity
- confidence
- reachable
- runtime observed
- language
- framework
- detector
- production/test/example

## 21.3 Finding詳細

```text
Rule
Severity
Confidence
Description
Why it matters
Source
Sink
Call path
Evidence
Remediation
References
```

## 21.4 受け入れ条件

- 単一HTMLでオフライン閲覧可能
- 外部CDN不要
- 大規模リポジトリで操作可能
- ノードクリックでfile:line表示
- GraphとFindingが相互リンク

---

# 22. テスト戦略

## 22.1 Unit Test

- Detector単位
- AST node単位
- Value Resolver単位
- Config Resolver単位
- Call Graph単位
- Policy単位
- Diff単位
- SARIF単位

## 22.2 Precision Test

以下を誤検知しない。

- コメント内モデル名
- README内サンプル
- docstring内API例
- regexパターン文字列
- importのみ
- 未使用変数
- テストfixture内文字列
- `mcpServers`という単語だけ
- AIに関するブログ文章
- package lock内の間接依存

## 22.3 Recall Test

以下を検出する。

- 変数経由モデル名
- 辞書経由設定
- YAML経由設定
- 環境変数デフォルト
- alias import
- wrapper関数
- factory pattern
- async call
- framework abstraction
- MCP tool
- LangGraph node
- FastAPI endpoint経由

## 22.4 Golden Test

既知のリポジトリスキャン結果をsnapshot化する。

## 22.5 受け入れ条件

- CIで全テスト実行
- Coverage 80%以上を目標
- Benchmarkのスコア低下を検知
- Precision/Recall閾値を設定
- SARIF schema validation
- CycloneDX schema validation

---

# 23. Black Hat Arsenal向けリポジトリ整備

## 23.1 必須ドキュメント

```text
docs/
├── architecture.md
├── detection-methodology.md
├── supported-frameworks.md
├── benchmark-methodology.md
├── threat-model.md
├── rule-reference.md
├── false-positive-handling.md
├── demo-guide.md
├── air-gapped-usage.md
├── limitations.md
└── contributing-detectors.md
```

## 23.2 Release

最低限以下を作る。

- `v0.1.0`
- GitHub Release
- Python wheel
- source archive
- Docker image
- checksum
- changelog
- demo data
- generated SBOM
- signed artifactが可能なら署名

## 23.3 Demo Repository

### Demo 1: Beginner

```text
Unpinned model
trust_remote_code=True
hardcoded API key
unsafe pickle
```

### Demo 2: Real World

```text
FastAPI
  -> LangGraph Agent
    -> RAG
      -> Model
        -> MCP Tool
```

### Demo 3: Enterprise Monorepo

```text
frontend/
backend/
model-service/
infra/
helm/
.github/workflows/
```

---

# 24. Black Hat向け5分デモ

## 0:00から0:30

通常SBOMではAI固有リスクが分からないことを説明。

## 0:30から1:30

```bash
aibom scan demo-app \
  --reachability \
  --html report.html
```

## 1:30から2:30

以下の攻撃面をGraph表示。

```text
Internet Endpoint
  -> Agent
    -> Unpinned Model
      -> Remote Custom Code
        -> MCP Shell Tool
```

## 2:30から3:30

Findingをクリックし、以下を表示。

- file:line
- Source
- Sink
- Call Path
- Capability
- Confidence

## 3:30から4:30

修正版との差分。

```bash
aibom diff before.json after.json
```

## 4:30から5:00

CI gateとSARIF。

```bash
aibom scan . \
  --policy policy.yaml \
  --sarif aibom.sarif \
  --fail-on high
```

---

# 25. 実装ロードマップ

## Sprint 1

- benchmark基盤
- Detector interface
- Python AST parser
- OpenAI detector
- Anthropic detector
- Hugging Face detector
- 変数解決
- 回帰テスト

## Sprint 2

- YAML/JSON/TOML resolver
- Usage state
- Confidence factors
- HTML evidence改善
- Benchmark結果公開

## Sprint 3

- Reachability
- FastAPI
- Flask
- CLI entrypoint
- Lambda
- Call Graph表示

## Sprint 4

- Prompt Source-to-Sink
- MCP Capability
- Attack Surface Graph
- 新ルール追加

## Sprint 5

- Diff
- SARIF
- Policy as Code
- GitHub Actions

## Sprint 6

- JavaScript/TypeScript parser
- Express
- Next.js
- Node OpenAI/Anthropic
- MCP TypeScript

## Sprint 7

- Runtime Evidence
- Plugin SDK
- Documentation
- Release
- Black Hat demo

---

# 26. 最重要の受け入れ基準

以下を満たすまでは「外部リポジトリ対応済み」としない。

1. 20件以上の公開リポジトリで評価している
2. 負例リポジトリを含む
3. カテゴリ別Precision/Recall/F1を公開
4. ASTによる検出がある
5. 変数経由のモデル名を解決できる
6. YAML/JSON/TOML設定値を解決できる
7. importだけと実呼び出しを区別できる
8. production/test/exampleを区別できる
9. file:lineの根拠がある
10. Reachabilityをtrue/false/unknownで表現できる
11. Low Confidenceを非表示にできる
12. SARIFをGitHub Code Scanningへ投入できる
13. DiffでAIサプライチェーン変更を検出できる
14. 単一HTMLでデモ可能
15. Known Limitationsを公開している

---

# 27. Claude Code / Codexへの実装指示

以下の手順で作業すること。

## Step 1

現在のコード構成、Collector、Rule Engine、CLI、出力形式、テストを調査する。

出力するもの:

- 現在のアーキテクチャ
- 変更対象ファイル一覧
- 後方互換性リスク
- 段階的移行計画

## Step 2

既存挙動を固定するGolden Testを追加する。

## Step 3

Detector interfaceを導入し、既存Regex検出をLegacy Detectorとして移行する。

## Step 4

Python AST parserとValue Resolverを追加する。

## Step 5

OpenAI、Anthropic、Hugging FaceのAST Detectorを実装する。

## Step 6

既存Regex結果とAST結果をDeduplicateする。

Deduplicateキー候補:

```text
entity_type
normalized_name
file
line
framework
```

## Step 7

Confidence factorsとResolution Pathを出力モデルへ追加する。

## Step 8

Benchmark harnessを作成する。

## Step 9

外部リポジトリで失敗するケースをテストとして追加する。

## Step 10

Reachability、Prompt、MCP、Diff、SARIFを順番に実装する。

---

# 28. 実装時の禁止事項

- 解析対象コードを実行しない
- `eval`、`exec`、import実行を使わない
- 推測値を確定値として出力しない
- 秘密値をレポートへ出力しない
- AST parse失敗時にスキャン全体を停止しない
- ネットワークアクセスを必須にしない
- 既存CycloneDX出力を破壊しない
- Regex検出を一度に削除しない
- 未解決値を誤って安全と判断しない
- 到達不能と解析不能を混同しない

---

# 29. 実装品質要件

- 型ヒント
- dataclassまたはPydantic
- 例外処理
- ロギング
- docstring
- 単体テスト
- 統合テスト
- schema validation
- stable JSON output
- semantic versioning
- changelog
- backward compatibility
- offline-first
- deterministic output

---

# 30. 最初に実装すべき5項目

1. 実リポジトリ評価ハーネス
2. Python AST + 軽量値解決
3. 使用状態の分類
4. Reachability Analysis
5. MCP / Prompt Source-to-Sink

機能数を増やすことより、以下を証明することを優先する。

- 実リポジトリで動く
- 誤検知が少ない
- 取りこぼしを数値化している
- 根拠を説明できる
- 本番入口から到達可能か分かる
- 修正前後の差分を示せる

---

# 31. 完成時の期待CLIデモ

```bash
git clone https://github.com/example/real-world-ai-app
cd real-world-ai-app

aibom scan . \
  --reachability \
  --policy ../policy.yaml \
  --html aibom-report.html \
  --sarif aibom.sarif \
  --format cyclonedx \
  --output bom.json
```

期待結果:

```text
AI components detected: 18
Reachable components: 9
High-risk findings: 4
Critical findings: 1
Unresolved values: 3
Low-confidence detections: 2
Policy result: FAILED
```

主要Finding:

```text
CRITICAL
LLM-reachable MCP tool can execute arbitrary shell commands.

Path:
POST /chat
  -> agent.invoke
    -> MCP run_command
      -> subprocess.run(shell=True)

Evidence:
app.py:42
agent.py:88
mcp_server.py:31
```

この状態をBlack Hat Arsenal向けの最終目標とする。
