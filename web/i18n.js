"use strict";
// Language switch (English / 日本語).
//
// English is the source text: it stays in index.html and app.js, so the page
// reads correctly even if this file fails to load. This file holds only the
// Japanese. Static elements carry data-i18n="key" (innerHTML) or
// data-i18n-attr="attr:key;attr:key"; app.js wraps its own strings in
// t(key, english). Scanner output (finding titles, evidence, fixes, rule text)
// comes from the API in English and is not translated.
// tests/test_web_ui.py fails when a key is used without a Japanese entry, or an
// entry is never used.

const LANG_KEY = "aibom.lang";

const JA = {
  "nav.skip": "リポジトリ解析へスキップ",
  "nav.analyze": "解析",
  "nav.compare": "変更の比較",
  "nav.help": "ヘルプ",
  "nav.docs": "ドキュメント ↗",

  "intro.title": "リポジトリの AI モデル・SDK・依存関係・リスクを確認する",
  "intro.body": "公開リポジトリの URL を貼り付けてください。AIBOM Inspector はコードとマニフェストをテキストとして読み、すべての依存関係と AI コンポーネントを一覧にし、既知の脆弱性と危険なエージェント経路を報告します。どの結果も、根拠となるファイルと行を示します。",

  "scan.title": "リポジトリを解析",
  "scan.repo": "リポジトリ URL",
  "scan.ref": "ブランチ・タグ・コミット <span class=\"optional\">任意</span>",
  "scan.refPlaceholder": "デフォルトブランチ",
  "scan.button": "リポジトリを解析",
  "scan.demo": "同梱サンプルで試す",
  "scan.or": "または",
  "scan.example": "公開リポジトリの例を入力",

  "sample.summary": "サンプルの内容",
  "sample.body": "AIBOM Inspector にテスト用として同梱している、2 ファイルの FastAPI + OpenAI Agents アプリです。意図的に脆弱にしてあり、リクエスト本文がエージェントの指示文に連結され、そのエージェントはシェルコマンドを実行するツールを呼べます。オフラインで解析し、実行はしません。",
  "coverage.summary": "解析する範囲・しない範囲",
  "coverage.list": "<li><strong>依存関係:</strong> requirements*.txt、pyproject.toml、Pipfile、package.json、go.mod、Cargo.toml、composer.json、Gemfile など。パッケージ間の関係は、それを記録するロックファイル（package-lock.json、poetry.lock、uv.lock、Cargo.lock、composer.lock、Gemfile.lock）からのみ得ます。</li><li><strong>AI コンポーネント:</strong> Python と JavaScript/TypeScript のソース中のモデル、プロバイダー、プロンプト、ツール、エージェント（OpenAI、Anthropic、Hugging Face、OpenAI Agents SDK、MCP サーバーと設定）。</li><li><strong>エージェントの権限:</strong> エージェントと IAM ポリシーファイルを対応づける <code>aibom-identity.yaml</code> がある場合のみ評価します。</li><li><strong>解析しないもの:</strong> 実行時に決まる値、動的にしか到達しないコード、非公開リポジトリ、2&nbsp;MB を超えるファイル。</li>",
  "data.summary": "データの送信先",
  "data.list": "<li>リポジトリは解析サーバーの一時ディレクトリに shallow clone され、解析の終了時に削除されます。結果はサーバーに保存されません。</li><li>脆弱性情報の照会のため、パッケージ名・エコシステム・正確なバージョンを <a href=\"https://osv.dev\" target=\"_blank\" rel=\"noopener noreferrer\">OSV.dev</a> に送ります。ライセンスとモデルカードの取得のため、Hugging Face のモデル・データセット ID を huggingface.co に送ります。</li><li>コードはテキストとして読むだけで、リポジトリ内のものは実行せず、モデルの重みも読み込みません。検出は AI モデルではなく決定的なルールによるものです。</li>",
  "adv.summary": "詳細設定: 解析バックエンド",
  "adv.label": "バックエンドのアドレス",
  "adv.save": "このバックエンドを使う",
  "adv.help": "リポジトリ URL と解析結果はこのアドレスとやり取りされます。<code>aibom serve</code> または Docker イメージで自分のバックエンドを起動できます。アドレスはこのブラウザにだけ保存されます。",

  "progress.cancel": "キャンセル",
  "progress.steps": "解析の段階",
  "stage.clone": "リポジトリを取得",
  "stage.collect": "ファイルとマニフェストを読み取り",
  "stage.lockfiles": "ロックファイルを解決",
  "stage.link": "コンポーネントを関連づけ",
  "stage.resolve": "Hugging Face のメタデータを取得",
  "stage.risk": "ルールを評価",
  "stage.vulns": "OSV で既知の脆弱性を照会",
  "stage.agents": "エージェント経路を解析",
  "stage.report": "結果を作成",
  "progress.waiting": "バックエンドの応答を待っています",
  "progress.elapsed": "{s} 秒経過",
  "progress.sample": "同梱サンプルを静的解析しています（clone・ネットワークなし）",
  "progress.noStages": "このバックエンドは段階を報告しません。clone、ファイルの読み取り、脆弱性の照会、レポート作成を順に行い、終了時に各段階の所要時間を表示します。",

  "status.scanning": "{repo} を解析しています…",
  "status.scanningAt": "{repo}（{ref}）を解析しています…",
  "status.scanningSample": "同梱サンプルアプリを解析しています（オフライン）…",
  "status.busy": "解析中…",
  "status.busySample": "サンプルを解析中…",
  "status.done": "解析が完了しました。",
  "status.sampleDone": "サンプルの解析が完了しました。結果の先頭にある検出内容から確認してください。",
  "status.failed": "解析を完了できませんでした",
  "status.sampleFailed": "同梱サンプルの解析を完了できませんでした",
  "status.keep": " 前回の結果を下に表示しています。",
  "status.cancelled": "キャンセルしました。バックエンドは次の段階に進む前に処理を中止します。",
  "status.cancelledOld": "キャンセルしました。画面は待機をやめましたが、バックエンドは処理を最後まで続けて結果を破棄する場合があります。",
  "status.needUrl": "解析するリポジトリの URL を入力してください。",
  "status.badUrl": "https:// から始まる完全なリポジトリ URL を入力してください。",
  "status.example": "例の URL を入力しました。準備ができたら解析を開始してください。",
  "stale.running": "新しい解析の実行中は、前回の結果を表示しています。",
  "stale.failed": "前回の結果を表示しています。最新の解析は完了しませんでした。",
  "results.overline": "解析結果",
  "results.overlineSample": "同梱サンプル · 解析結果",
  "results.langNote": "検出内容のタイトル・根拠・修正方法、表の中身などスキャナーが出力する本文は英語のまま表示します。",

  "headline.action_required": "対応が必要",
  "headline.review": "確認を推奨",
  "headline.no_findings": "適用したルールでは検出なし",
  "headline.detailAction": "{parts} の検出があります。このコードを使う前に修正してください。",
  "headline.detailReview": "{parts} の検出があります。critical・high の検出はありません。",
  "headline.detailNone": "解析した範囲ではどのルールにも該当しませんでした。リポジトリが安全である証明ではありません。解析の制限を確認してください。",
  "sum.findings": "件の検出",
  "sum.noneApplied": "適用したルールでは検出なし",
  "sum.packages": "パッケージ",
  "sum.packagesNote": "直接 {direct} · 推移的 {transitive} · 関係が判明 {resolved}",
  "sum.vulnerable": "脆弱なパッケージ",
  "sum.vulnerableNote": "修正版が判明 {n}",
  "sum.ai": "本番コードの AI コンポーネント",
  "sum.aiNote": "テスト・例・ドキュメントにさらに {n}",
  "sum.paths": "入力→ツール経路",
  "sum.pathsNote": "信頼できない入力が、エージェントに結び付いたツールに届きます",
  "sum.agents": "エージェント",
  "sum.start": "まず確認:",
  "sum.limits": "解析の制限",

  "exp.html": "HTML レポート<small>共有用</small>",
  "exp.htmlTitle": "人に共有するための単体のページ",
  "exp.cdx": "CycloneDX<small>SBOM ツール用</small>",
  "exp.cdxTitle": "Dependency-Track などの SBOM ツール向けの CycloneDX 1.6 SBOM",
  "exp.sarif": "SARIF<small>コードスキャン用</small>",
  "exp.sarifTitle": "GitHub code scanning 向けの SARIF 2.1.0",
  "exp.inv": "インベントリ JSON<small>生データ</small>",
  "exp.invTitle": "検出したすべてのエンティティと関係の生 JSON",

  "tab.findings": "検出内容",
  "tab.deps": "依存関係",
  "tab.graph": "AI 利用マップ",
  "tab.agent": "エージェント経路",
  "tab.inventory": "インベントリ",
  "tab.compliance": "SBOM 項目",

  "findings.desc": "まず脆弱なパッケージを、修正版が判明しているすべてのアドバイザリを解消する 1 つのアップグレード先とともに示します。続いてコードと設定の検出内容（影響・根拠・修正方法）です。",
  "findings.search": "検出内容を検索",
  "findings.allSev": "すべての重大度",
  "findings.code": "コードと設定の検出内容",
  "col.severity": "重大度",
  "col.rule": "ルール",
  "col.impact": "影響 · 根拠 · 修正方法",
  "col.location": "場所",
  "score.summary": "サプライチェーン衛生スコア（参考）",
  "score.help": "検出した AI コンポーネントの衛生状態を測るスコアです。完全性・来歴・ライセンス・設定の各カテゴリが 100 から始まり、critical / high / medium / low の検出 1 件ごとに 40 / 20 / 10 / 3 点を引きます（1 ルールにつき最大 3 件）。総合点は平均と最も低いカテゴリを重み付けしたものです。合否の判定ではありません。結果の先頭に示す状態は、最も重い検出で決まります。",

  "deps.search": "パッケージを検索",
  "deps.all": "すべてのパッケージ",
  "deps.direct": "直接依存のみ",
  "deps.transitive": "推移的依存のみ",
  "deps.ai": "AI パッケージ",
  "deps.findings": "検出あり",
  "deps.unknown": "関係が不明",
  "col.package": "パッケージ",
  "col.version": "バージョン",
  "col.scope": "範囲",
  "col.dependsOn": "依存先",
  "col.requiredBy": "依存元",
  "col.declaredIn": "宣言場所",

  "legend.noFinding": "検出なし",
  "agent.desc": "どのエージェントがどの MCP サーバーを経由して、どのツールとクラウド操作に到達できるか、そして与えられた ID ポリシーがそれを許可するかを示します。静的な経路は実証された攻撃ではありません。「許可の可能性あり」は与えられた ID ポリシーだけで判断しており、AWS の実効的な認可ではありません。解決できなかったつながりは <strong>Unknown</strong> と表示し、安全とはみなしません。",
  "legend.allowed": "許可の可能性あり",
  "legend.denied": "明示的に拒否",
  "legend.nomatch": "一致する許可なし",
  "legend.unknown": "不明",
  "legend.dormant": "定義のみ（未公開）",

  "inv.desc": "テスト・例・ドキュメントのファイルも含め、スキャンで見つかったものすべてです。<strong>エントリポイント到達性</strong>は、静的解析でコンポーネントを本番のエントリポイントに結び付けられたかを示します。「unknown」は判断できなかったという意味で、到達しないという意味ではありません。ツールとエージェントの結び付きはエージェント経路に表示します。",
  "inv.search": "インベントリを検索",
  "inv.allTypes": "すべての種類",
  "inv.allContexts": "すべてのコンテキスト",
  "inv.anyReach": "到達性を問わない",
  "inv.reachable": "到達する",
  "inv.notReachable": "到達しない",
  "inv.reachUnknown": "到達性が不明",
  "inv.na": "該当なし",
  "col.type": "種類",
  "col.name": "名前",
  "col.provider": "提供元 / ソース",
  "col.usage": "利用状況 · エントリポイント到達性",
  "col.context": "コンテキスト",
  "col.evidence": "根拠",

  "sbom.title": "SBOM 項目（CISA 2026 最小要素）",
  "sbom.desc": "生成した CycloneDX ファイルが、CISA の 2026 年版 SBOM 最小要素に挙げられた項目をどこまで埋めているかを示します。このツールが出力したファイルの機械的なチェックであり、認証やリポジトリの監査ではありません。<strong>Filled</strong>: 根拠から記入。<strong>Partly filled</strong>: 一部のコンポーネントのみ記入。<strong>Declared unknown</strong>: 静的解析では知り得ず、ファイルにその旨を明記。",
  "col.status": "状態",
  "col.element": "要素",
  "col.since": "導入時期",
  "col.coverage": "充足度",
  "col.cdxField": "CycloneDX のフィールド",

  "help.reposTitle": "対応するリポジトリ",
  "help.repos": "<li>github.com、gitlab.com、bitbucket.org、codeberg.org の公開リポジトリ（<code>https://host/owner/repository</code> の形式）。</li><li>任意: 2 つ目の欄にブランチ、タグ、または完全なコミット SHA。</li><li>対応しないもの: 非公開リポジトリ、GitLab のサブグループ、ファイルやフォルダへのリンク（<code>/tree/…</code>、<code>/blob/…</code>）、その他のホスト。</li>",
  "help.limitsTitle": "制限と失敗時の対処",
  "help.limits": "<li>clone は 120 秒でタイムアウトします。300 MB または 60,000 ファイルを超えるチェックアウトは拒否します。大きなリポジトリはローカルのチェックアウトに CLI を使ってください。</li><li>「No analysis backend」: このページは画面だけです。<em>詳細設定</em>でバックエンドを指定してください。</li><li>脆弱性情報の照会に失敗した場合は結果の<em>解析の制限</em>に表示し、「脆弱性なし」とは報告しません。</li>",
  "help.examplesTitle": "目的別の例",
  "help.examples": "<li><strong>依存関係と脆弱性情報:</strong> <button class=\"link\" type=\"button\" data-example=\"https://github.com/openai/openai-quickstart-python\">openai/openai-quickstart-python</button>（エージェントなし・パッケージ多数）。</li><li><strong>エージェントとツールの経路:</strong> <button class=\"link\" type=\"button\" data-example=\"demo\">同梱サンプル</button>。</li><li><strong>リビジョン間の変更:</strong> <a href=\"#compare\">変更の比較</a>（同梱デモまたは自分のリポジトリ）。</li>",
  "help.cliTitle": "コマンドライン",
  "help.cli": "<li><code>pip install \"aibom[server]\"</code> のあと、ローカルのチェックアウトに <code>aibom scan PATH</code>（非公開のコードが手元の外に出ません）。</li><li><code>aibom diff BASE HEAD --fail-on high</code> は新しい危険な経路があると CI を失敗させます。<code>--agent-privileges</code> を付けるとエージェントの権限も比較します。</li>",

  "cmp.title": "2 つのリビジョン間の変更を比較",
  "cmp.body": "同じリポジトリの 2 回のスキャンを、別々の観点で比較します。コンポーネントが変わったか、信頼できない入力からエージェントが呼べるツールへの新しい経路が生じたか、エージェントがクラウド権限を得たか。コンポーネントの一覧が同一のまま、ほかの 2 つが変わることもあります。",
  "cmp.formTitle": "自分のリポジトリ",
  "cmp.base": "比較元",
  "cmp.head": "比較先",
  "cmp.headPlaceholder": "ブランチ、タグ、コミット SHA",
  "cmp.run": "比較",
  "cmp.help": "比較対象: モデル、パッケージ、サービス、ツール（プロンプトは経路として比較）、入力→ツール経路、そしてエージェントと IAM ポリシーファイルを対応づける <code>aibom-identity.yaml</code> がある場合はエージェントの権限（ない場合はその部分を「未評価」と報告）。CI では <code>aibom diff</code> に <code>--fail-on high</code> を付けて実行してください。",
  "cmp.demoHeading": "同梱データによる例 <span class=\"demo-badge\">デモ</span>",
  "cmp.demoHelp": "AIBOM Inspector に同梱したテスト用データでオフライン実行します。比較で何が報告されるかを示すもので、あなたのコードを解析・検証するものではありません。",
  "cmp.pathTitle": "新しい入力→ツール経路",
  "cmp.pathBody": "ルート、プロンプト生成、エージェント、ツールが 4 ファイルにまたがります。比較先ではリクエストのデータがエージェントの指示文に連結されます。",
  "cmp.demoPy": "Python デモ",
  "cmp.demoTs": "TypeScript デモ",
  "cmp.fixed": "同梱の修正済みリビジョン",
  "cmp.privTitle": "エージェント権限の変更",
  "cmp.privBody": "コードは同じでも、ID ポリシーが広がる、または MCP ツールのフィルターが外れることで、読み取りしかできなかったエージェントが書き込めるようになります。",
  "cmp.policyOnly": "ポリシーのみの変更",
  "cmp.mcpRemoved": "MCP ツールフィルターの削除",
  "cmp.pathChanges": "経路の変化",
  "cmp.pathHelp": "重大度は、ツールが到達できる操作の潜在的な影響です。根拠は経路のどこまでを実証できたかです。<strong>Proven statically</strong>（すべての段階を解決）、<strong>Potential</strong>（仮定が必要。Critical にはしない）、<strong>Unknown</strong>（表示のみで CI は失敗させない）。ノードを選ぶと、ファイル・行・制限を表示します。",
  "cmp.other": "その他の変更",
  "col.kind": "種別",
  "col.change": "変更",
  "cmp.demoResult": "デモ結果 · 同梱データ",
  "cmp.show": "表示:",
  "cmp.highlighted": "強調表示: 比較元に対して追加・変更されたもの。",
  "cmp.whatChanged": "変化した点: 影響 · 根拠 · 修正方法",

  "footer.tagline": "AIBOM Inspector · 根拠に基づく静的なリポジトリ解析",
  "footer.source": "ソース",
  "footer.method": "検出の方法",
};

let currentLang = "en";
const EN_TEXT = new WeakMap();

function storedLang() {
  try { return localStorage.getItem(LANG_KEY); } catch (_) { return null; }
}

function initialLang() {
  const stored = storedLang();
  if (stored === "en" || stored === "ja") return stored;
  const nav = (navigator.languages && navigator.languages[0]) || navigator.language || "";
  return nav.toLowerCase().startsWith("ja") ? "ja" : "en";
}

// The Japanese for `key`, or the English given by the caller. `{name}` slots
// are filled from `vars` in either language.
function t(key, en, vars) {
  let s = currentLang === "ja" && JA[key] != null ? JA[key] : en;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] != null ? String(vars[k]) : m));
  return s;
}

function applyStaticText() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const en = EN_TEXT.get(el) || {};
    if (en.html == null) { en.html = el.innerHTML; EN_TEXT.set(el, en); }
    const ja = JA[el.dataset.i18n];
    el.innerHTML = currentLang === "ja" && ja != null ? ja : en.html;
  });
  document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
    const en = EN_TEXT.get(el) || {};
    EN_TEXT.set(el, en);
    for (const pair of el.dataset.i18nAttr.split(";")) {
      const [attr, key] = pair.split(":");
      const slot = "attr:" + attr;
      if (en[slot] == null) en[slot] = el.getAttribute(attr) || "";
      el.setAttribute(attr, currentLang === "ja" && JA[key] != null ? JA[key] : en[slot]);
    }
  });
}

function setLang(lang, remember) {
  currentLang = lang === "ja" ? "ja" : "en";
  document.documentElement.lang = currentLang;
  applyStaticText();
  const toggle = document.getElementById("langToggle");
  if (toggle) {
    // The button names the *other* language, in that language.
    toggle.textContent = currentLang === "ja" ? "English" : "日本語";
    toggle.lang = currentLang === "ja" ? "en" : "ja";
    toggle.setAttribute("aria-label", currentLang === "ja" ? "Show in English" : "日本語で表示");
  }
  const note = document.getElementById("langNote");
  if (note) note.hidden = currentLang !== "ja";
  if (remember) {
    try { localStorage.setItem(LANG_KEY, currentLang); } catch (_) { /* per-browser only */ }
  }
  document.dispatchEvent(new CustomEvent("aibom:lang", { detail: currentLang }));
}
