// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
const SYSTEM_PROMPT: &str = "You are an operations assistant.";

async fn run(client: &Client) {
    let request = CreateChatCompletionRequestArgs::default().model("gpt-4o-mini");
}
