# AIBOM Inspector — Agent Identity & Privilege Drift 拡張設計・実装指示書

> **対象リポジトリ**: https://github.com/d01ki/AIBOM-Inspector  
> **実装担当**: Claude Code  
> **位置付け**: Black Hat Asia 2027 Arsenal向け、既存ツールの実証可能なセキュリティ機能拡張  
> **中心命題**: **The AI-BOM stays the same. The agent's effective capabilities change.**  
> **仕様方針**: 日本語、推測を事実と区別し、テスト可能な振る舞いを定義する。

## 0. Claude Codeへの実行指示（最初に読む）

この設計書を実装仕様として扱う。**計画だけで終了せず、P0を実装・テスト・デモ・ドキュメントまで完成させること。** リポジトリを最初に調査し、既存機能を重複実装しない。設計書内のファイル名・配置例は提案であり、現行構成と不整合なら既存アーキテクチャに沿って変更する。

開始時に以下を確認する。

1. `git status`、最近のコミット、README/SPEC、`docs/architecture.md`、`docs/limitations.md`、`docs/novelty-positioning.md`、tests、benchmark。
2. Python / JS/TSのコンポーネント抽出、prompt-flow、impact-path、diff、CycloneDX、CLI/API/UIの現在のインターフェース。
3. 既存のAI Agent、MCP、Cloud/IAM、権限・構成データの取得能力。未実装を実装済みと仮定しない。
4. ベースラインテストを実行し、結果と既知の失敗を記録。
5. 作業ブランチを使用し、差分を小さく段階的に適用。既存の公開CLI/API/JSON/CycloneDX出力を破壊しない。

**安全条件**: 対象OSSのコード、MCP server、Agent、tool、任意のスクリプトは実行しない。`pip install` / `npm install` / provisioning / IAM変更 / 実クラウドへの権限使用 / シークレット収集はしない。解析は静的・ローカル優先。任意リポジトリ内の設定ファイルを実行可能な指示として扱わない。クラウド接続はP2以降の別設計。

## 1. 研究目的と差別化

既存AIBOM Inspectorは、AIモデル/Agent/MCP/Prompt/Toolを抽出し、Trust Boundary・Tool Reachability・Behavioral Driftを静的に解析する。本拡張では、これらに **Identity → Permission → Resource → Capability** を結び付け、**AI-BOMに変更がなくても、認可設定・Credentialの結び付き・Toolの許可範囲が変われば、Agentの潜在的操作能力が増大する**ことを検出する。

主張する価値：

- Agent / Tool / Identity / Permission / Resource 間の**根拠付き関係**を作成する。
- 明示的な権限・委任設定と、コード上のTool Bindingを交差解析する。
- 変更前後で**新たに許可される可能性のある操作**とその原因設定を提示する。
- 修正候補を提示し、同じ条件で再スキャンして改善を検証する。

**新規性を言い過ぎない。** Agent Identityの発見、IAM解析、MCP可視化、AIBOM出力、差分検出はそれぞれ既存分野にある。競合比較で新規性が検証されるまで「世界初」「唯一」「実際の権限逸脱を証明」と記載しない。

## 2. スコープと優先順位

| 優先度 | 実装 | 必須完了条件 |
|---|---|---|
| **P0-1** | 静的Agent Identity / Capabilityデータモデル | JSON出力・Evidence・Unknownを含み、既存データと後方互換 |
| **P0-2** | 明示的なAgent→Tool→Identity関連付け | Python OpenAI Agents SDK等、**サポートを宣言した限定パターン**で実証 |
| **P0-3** | オフラインIAM Policy解析（AWSの限定サブセット） | Identity policy + 明示的Tool操作との照合。Allow/Deny/Unknownを区別 |
| **P0-4** | Agent Privilege Drift | BOM同一・Policy変更で新規capabilityを検出。差分の根拠を提示 |
| **P0-5** | 修正・再検証デモ | Before/After/Fixの3段階、CLIで1コマンド、自己完結型サンプル |
| **P0-6** | テスト・README・限界・短いArsenal説明 | 正例・負例・Unknown・再現可能な報告 |
| **P1** | JS/TS、MCP設定、cross-file、明示的委任、Graph UI、SARIF | 各機能にテストと実証済みマトリクス |
| **P2** | Azure/GCP/OAuth、クラウド実効権限、実行時観測 | 将来構想。今回のMVPで対応済みと書かない |

**締切・時間が厳しいときはP0優先。広く浅い認識パターンより狭く厳密な検出を優先。**

## 3. 非目標（必ず明文化）

- AWS全IAM評価エンジンの再実装、Organizations SCP、Permission Boundary、Session policy、Resource policy、KMS key policy、IAM condition全般、AssumeRole実際の成立保証。
- 動的Agentの意思決定、Prompt Injection成功率、任意LLMのTool選択結果の保証。
- ソースコードのみから実際のクラウドPrincipalや権限を断定すること。
- 発見したAgentを自動的に**Shadow**と断定すること。管理台帳未入力は `management_status=unknown`。
- Agent間委任による現実の権限昇格を静的解析だけで「実証済み」とすること。
- SBOMのCISA 2026最小要素への完全準拠宣言。既存のConformance Checkerは維持し、公式文書との未照合事項を明記。

## 4. 入力・出力の仕様

### 4.1 入力（最初はローカルのみ）

- 解析対象のソースコードと既存AIBOM inventory。
- 明示的なAgent-to-Identityマッピングファイル `aibom-identity.yaml`（新規・任意）。
- IaC/ポリシーとして読めるローカルIAM JSON（独立したAWS policy subset）。
- `aibom.toml` による設定と、CLI引数で与えたベースライン/候補ディレクトリ。
- 登録台帳 `approved_agents.yaml` はP1。存在しない場合はShadowとは判定しない。

提案する `aibom-identity.yaml`（**仮のIDを用いる安全なデモ専用例**）：

```yaml
schema_version: 1
agents:
  - agent_ref: "agent:reviewer"
    source: "app/agent.py:reviewer"
    identity_ref: "aws:role/demo-review-role"
identities:
  - id: "aws:role/demo-review-role"
    provider: aws
    policies:
      - "policy/review-role.json"
    provenance: "explicit_manifest"
```

入力YAML/JSONにはサイズ制限、パス正規化、workspace外参照の禁止、シンボリックリンク対応、スキーマ検証を行う。`agent_ref` を解決できない場合はUnknownを返し、勝手に結び付けない。Credential本文は保存も表示もしない。

### 4.2 グラフのノード・エッジ

**Node**: `agent`, `model`, `prompt`, `tool`, `identity`, `policy`, `permission`, `resource`, `operation`, `input_source`。

**Edge**: `BINDS_TOOL`, `RUNS_AS`, `ATTACHES_POLICY`, `ALLOWS_ACTION`, `DENIES_ACTION`, `TARGETS_RESOURCE`, `MAY_INVOKE`, `REACHES_OPERATION`, `DELEGATES_TO`（P1）、`TRUST_BOUNDARY_CROSSES`（既存から再利用）。

各ノード・エッジに`id`、`evidence[file,line,kind]`、`source_type`（observed_static/explicit_manifest/inferred/unknown）、`confidence`（0–1、任意）、`resolution_status`を付与する。

エッジを単に文字列一致で生成しない。`agent -> identity` は明示設定か信頼できる限定されたコードパターンのみ。`identity -> allowed` はpolicy解析スコープと条件を満たす場合のみ。`tool -> operation` は既存のbinding/operation解析で根拠がある場合のみ。

### 4.3 Capability Verdict

```json
{
  "agent_id": "agent:reviewer",
  "identity_id": "aws:role/demo-review-role",
  "tool_id": "tool:repo_writer",
  "action": "s3:PutObject",
  "resource": "arn:aws:s3:::demo-assets/*",
  "verdict": "potentially_allowed",
  "confidence_level": "conditional",
  "constraints": ["identity-policy-only", "runtime-identity-unverified"],
  "evidence": [{"file": "policy/review-role.json", "pointer": "/Statement/0"}],
  "proven": false
}
```

`potentially_allowed` はAWSの**実効権限の保証ではない**。実効的な権限を確定できない場合は `unknown` か `potentially_allowed`（制約明示）を使う。`explicitly_denied`、`no_matching_allow_in_supplied_policies` とも区別する。**No matching allow ≠ 実際の操作不可**。未提供ポリシーを無視して安全判定しない。

## 5. P0 実装の詳細

### P0-1: モデル層

- 既存`src/aibom`のmodels/schemaを拡張。`AgentIdentity`, `AuthorizationPolicy`, `Permission`, `CapabilityPath`, `PrivilegeChange`, `RemediationAdvice`を追加。
- 新フィールドは原則optional、既存のJSON/SARIF/CycloneDX形式を破壊しない。既存のリスクスコアと区別して`agent_security`名前空間へ出力。
- Schema versionを付与し、将来の互換移行を可能にする。

### P0-2: Agent / Tool / Identityの解決

- 対応範囲を最初はPython OpenAI Agents SDKの**明示的な**Agent定義・Tool Bindingと、ユーザー提供のIdentityマッピングに限定。
- 既存AIBOMのAgent/Tool検出結果と整合し、同じcomponent IDを使う。Tool名だけで異なるコードを連結しない。
- `RUNS_AS`を推定で補完しない。未対応構造はUnknownとし、解析対象・欠落理由を機械可読で記録。
- AgentがAgent Bを利用するだけで「委任済み権限昇格」と報告しない。

### P0-3: AWS IAM JSONの厳格な限定評価

対応：`Effect`(Allow/Deny)、`Action`（単一/配列、限定的ワイルドカード）、`Resource`（単一/配列）、明確な `Statement` マッチ。`Deny`が一致した場合は優先。

未対応：`NotAction`, `NotResource`, `Condition`（評価文脈を含めて正確に評価できるまではUnknown）、Resource-based policy、SCP、Boundary、Session、Role Trust Policy、サービス固有の複雑な意味論。

サポートしていない構文を検出したら、肯定的判定を返さずUnknownにフォールバック。欠落ポリシーのケースもUnknown。AWS実行環境へのアクセス不要。`iam:PassRole`や`sts:AssumeRole`を自動的に成功した委任とみなさない。

Capability解析はアクション辞書（例: `s3:GetObject`, `s3:PutObject`）をサポートし、認識できるTool操作だけに対応。`repo_writer` と S3操作を結び付けるには明示的マッピングやコード上の根拠が必要。

### P0-4: Privilege Drift検出

入力は`baseline/` と `candidate/`。既存diff処理と統合するが、コンポーネントDiffとは**独立したSecurity-Semantic Diff**を出す。

- 正規化されたstable ID (`agent`, `identity`, `tool`, `action`, `resource`) による比較。ソース行番号だけでIdentityを決めない。
- 比較対象の証拠範囲、未解決事項、権限ポリシーの可視範囲が一致しているか確認。
- 発見例：`privilege_path_added`, `permission_scope_expanded`, `privileged_identity_binding_added`, `potential_privilege_removed`。
- `baseline=unknown`, `candidate=potentially_allowed` は**confirmed_added**でなく`review_required`。欠落データだけによる「新規Critical」を禁止。
- severityは確定的危険操作・外部入力到達・修正容易性などに基づき説明可能なルールで付与。重大度と証拠確実性を別軸にする。実際の侵害やExploit成功を示す表現は禁止。

差分JSON例:

```json
{
  "type": "permission_scope_expanded",
  "change_status": "supported",
  "bom_components_unchanged": true,
  "agent": "agent:reviewer",
  "before": ["s3:GetObject"],
  "after": ["s3:GetObject", "s3:PutObject"],
  "affected_resource": "arn:aws:s3:::demo-assets/*",
  "severity": "high",
  "certainty": "conditional",
  "evidence": ["policy/review-role.json#/Statement/0"],
  "remediation": "Remove the unnecessary PutObject permission or narrow its resource scope."
}
```

このJSONは設計例であり、測定済み結果ではない。

### P0-5: Evidence-based Remediation / Verify

- Findingごとに`why_it_matters`、`source_evidence`、`conditions`、`recommended_actions`、`retest_command`を持つ。
- 対応可能な場合は「不要Action削除」「Resourceを限定」「AgentとIdentityのBinding見直し」「承認を追加」など**提案**する。
- 自動でIAM policyやユーザーのコードを書き換えない。
- 推奨の修正後の再解析でFinding消失を記録。Unknownを0件にすることで「修正済み」判定にしない。

### P0-6: CLI/API/UI 最小実装

現行CLIを確認して自然なサブコマンドを追加する。例：

```bash
./aibom scan ./examples/agent-identity/baseline --identity-manifest aibom-identity.yaml
./aibom diff ./examples/agent-identity/baseline ./examples/agent-identity/candidate --agent-privileges
./aibom demo --scenario agent-privilege-drift
```

このCLI例は**目標仕様**であって現在動くと主張しない。実装後、`--help` と実例が一致するようREADMEを更新。

- CLI出力には1) BOM unchanged 2) New capability path 3) Changed policy 4) Confidence / Unknown 5) Remediation 6) Retestを簡潔に表示。
- Web UIは既存グラフの拡張として**P1**。P0はCLI + 自己完結HTML/JSONなど実装コスト最小の形式で良い。時間不足で見た目優先にしない。
- HTML/JSONにCredentialやPrompt本文を含めない。

## 6. P1: MCP / Cross-file / Delegation の拡張

### P1-A MCP Capability Graph

`mcpServers`やSDK構成、Tool Schema、明示的なTool Nameを検出し、MCP Client→Server→Toolの接続を証拠付きで表現。MCP Toolの**存在**とAgentに**実際にBindingされていること**を区別。MCP Serverを起動して動的列挙しない。

### P1-B Cross-file lineage

Python import/明示的な関数・定数参照、JS/TS import/export・単純なwrapperを境界付きで解析。既存のbounded call graphを再利用し、循環/未解決はUnknown。新しいPrivilege Pathが生成された場合はファイル・行・シンボルを追跡。

### P1-C Delegation Drift

明示的なHandoff/Agent-as-tool構造を抽出するが、**子Agentが持つ権限の単純な和集合を親Agentの実効権限として扱わない**。Handoffガード、承認、Identityコンテキスト伝播が不明なら`potential_delegate_path` + Unknownとする。

### P1-D Shadow Agent（オプション）

ユーザーから承認済みAgent台帳が提供された場合のみ、検出Agentとの差分を`unregistered`とする。台帳なしでは`unverified`。名称の誤差やエイリアスを扱えるID設計。Shadow AIサービスのトラフィック可視化は対象外。

## 7. デモシナリオ（実装に必須）

同一のAIアプリ、同一モデル、同一Agent、同一Tool、同一パッケージ構成で3状態を作る。**サンプルは意図的に静的解析が追える明示設定にし、検出できない複雑なシステムを装わない。**

**Baseline**: Reviewer Agent + read-only policy (`s3:GetObject`) → inventory生成、危険経路追加なし。

**Candidate**: コードとコンポーネントは変更せず、同じRoleのpolicyに` s3:PutObject`を追加。該当操作とAgentのTool Bindingに裏付けがあるときだけ`permission_scope_expanded`を報告。もしTool操作が直接裏付けられない場合は`identity_permission_expanded`として別分類し、「AgentがPutObjectを実行可能」と断定しない。

**Fixed**: Role policyを最小権限へ戻す → 新規のPrivilege Driftがなくなることを検証。

各段階のCLI出力、Finding JSON、Evidence graph、diff結果を保存し、`./aibom demo --scenario agent-privilege-drift`などでオフライン再現可能にする。デモの検出件数や成功率は実行後に計測して記載。

## 8. テストケースと受入基準

| ケース | 期待結果 |
|---|---|
| `GetObject` → `GetObject + PutObject` | 権限拡大を検出。Toolと操作の関係が裏付けられればcapability pathに昇格 |
| `PutObject` → `GetObject` | 権限縮小として検出。高危険Finding新規発生なし |
| 同じpolicy、ファイル行番号だけ変更 | Driftなし |
| DenyがAllowと同時一致 | `explicitly_denied`、potential allow扱いしない |
| 未対応Condition/NotAction/NotResource | Unknown。安全・危険と断定しない |
| policyファイル欠落・Identity未解決 | Unknown + 理由。Criticalなし |
| Agent名が同じ、別ファイルで別Identity | 根拠IDで区別。誤結合なし |
| BOM同一、policyのみ変更 | BOM unchanged = true、security drift = true |
| `unknown` → `potentially_allowed` | `review_required`、confirmed driftではない |
| 未使用/非BindingのTool | 直接のcapability pathを生成しない |
| Secret文字列入りfixture | report, logs, SARIFに原文が出ない |
| 悪意のあるYAMLパス・外部参照 | workspace外読み取り禁止、入力エラーとして終了 |
| 既存scan/diff/demo/CycloneDX | 回帰テストが通る |

**Definition of Done**

- [ ] P0でサポートするフレームワークと権限解析の範囲をコードとdocsに明記。
- [ ] Baseline / Candidate / Fixedのデモがオフラインで再現可能。
- [ ] 最低1つの真陽性、3つ以上の明確な負例、Unknownを検証するテストを追加。
- [ ] 正しいstable IDとEvidenceで根拠を追跡できる。
- [ ] Existing API/CLI/exportsの回帰テストが通る。
- [ ] 未対応IAM要素で誤ったallow/safe/criticalを報告しない。
- [ ] README、architecture、limitations、example、短いdemo scriptを更新。
- [ ] Black Hat向けの新規性説明を、実際に実装・検証した能力のみに限定。

## 9. 開発順序（Claude Code向け）

1. リポジトリ調査・既存テスト実行・P0実装箇所の特定。
2. スキーマ追加、構造化Evidenceと後方互換テスト。
3. Identity Manifest parser、Path安全性、Agent/Tool連携。
4. AWS IAM subset parser/evaluatorとUnknown semantics、単体テスト。
5. Capability pathとPrivilege Drift、差分レポート。
6. 3段階デモとCLI/JSON/HTML（可能な範囲）出力。
7. README・アーキテクチャ図・限界・再現コマンド。
8. 余力がある場合のみP1へ進む。

各フェーズ終了時に **実装ファイル、テスト実行コマンドと結果、未完成事項** を報告する。完了していない機能をREADMEのFeaturesに記載しない。ブランチのpushやPR作成はユーザーの既存運用に合わせ、許可なくmainへ直接pushしない。

## 10. 計測・研究の評価設計

AIBOMの検出精度とは別に、以下を測る。

- **Identity linkage precision/recall**: 正解データで検証したAgent↔Identityの関係。
- **Privilege drift precision/recall**: 変更あり/なしのラベル付きfixtureとOSS実例で測定。
- **False positive causes**: unknown policy、動的binding、未対応IAM Condition、同名Agentの混同。
- **Evidence quality**: 各Findingに検査者が再確認できる根拠がある割合。
- **Performance**: リポジトリサイズ別の解析時間・メモリ。
- **Comparative demo**: 同一BOMでIAM policyだけ変更したケースを、通常SBOM diff / 現行AIBOM diff / 拡張版で比較。競合ツールが対応できないと断言せず、実行して確認した結果のみ記載。

少数のfixtureだけで100%精度と主張しない。外部OSSはコミットSHA固定、正解データの作成手順、検証環境、失敗例を公開する。

## 11. CISA 2026・CycloneDXとの整合

- 既存のCycloneDX 1.6 ML-BOM、SBOM生成、CISA conformance functionalityを維持。
- Agent Identity / privilegeは独自プロパティや別JSON graphに出力してよいが、標準のフィールドであるかのように装わない。
- `docs/cisa-2026-minimum-elements.md` は元の実装時に公式PDF本文を直接検証できなかった旨を記載している。**公式Appendix Aと実装 `minimum_elements.py` を再照合**し、未確認なら完全準拠と称さない。
- 署名、component hash、license、lockfile coverageの未取得・不明・外部依存はレポート内で透明に示す。
- 将来の標準でAgent Identity属性が追加されても移行可能なversioned schemaとする。

## 12. Black Hat Arsenal発表構成

推奨する説明：

> **Beyond AI-BOM: Detecting Agent Privilege Drift and Hidden Capability Expansion**
>
> Traditional SBOM and AI-BOM inventories describe what components exist. They do not necessarily reveal how an AI agent's permitted actions change when identities or policies change. This extension links AI components, tool bindings, identity mappings, and bounded authorization evidence to detect security-significant capability drift—even when the component inventory remains unchanged.

デモ進行（約4–6分の構成案、実際の枠時間に合わせ調整）：

1. AIBOM Discovery（現行資産）
2. Baseline（read-only Agent）
3. Policy-only change → BOM unchanged
4. Privilege drift → path and evidence
5. Fix → retest → Findingの消失
6. Limitationsと他ツールとの差異

「AWS IAMが変わると危険」だけでは一般的なIAM構成差分にすぎない。**AI Agentの実際のTool Binding・操作との関連、権限変化をエージェント固有の経路として証明できること**が発表の核。単純なPolicy変更だけを表示して終わらない。

## 13. 関連情報

- Existing project: https://github.com/d01ki/AIBOM-Inspector
- Previous plan: `AIBOM_Inspector_BlackHat_Asia_2027_Implementation_Plan.md`（存在する場合に参照。独立した仕様として本書だけでも実装可能）
- CISA 2026 SBOM minimum elements: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom
- CycloneDX: https://cyclonedx.org/
- Existing files to inspect: README.md, SPEC.md, docs/limitations.md, docs/architecture.md, docs/cisa-2026-minimum-elements.md, benchmark/reports/external-latest.md

---

## Claude Codeに与える開始プロンプト

```text
Read AIBOM_Inspector_Agent_Identity_Privilege_Drift_Design.md and implement it in this repository.
Start by inspecting the actual code, its architecture, current tests, and working tree. Reuse existing AIBOM inventory, prompt-flow, impact-path, and diff components rather than duplicating them.
Prioritize P0 end-to-end: identity/permission models, explicit mappings, bounded IAM evaluation with Unknown semantics, agent capability linkage, privilege drift, a reproducible offline baseline/candidate/fixed demo, tests, and documentation.
Do not execute scanned repositories or real agent tools, collect credentials, modify cloud permissions, or claim effective authorization beyond the available evidence.
Keep all existing CLI/API/CycloneDX behavior backwards compatible. Implement incrementally and run regression tests. Report what is completed and verified and what remains unimplemented. Do not stop after writing a plan.
```
