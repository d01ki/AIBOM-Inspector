// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
public class Agent {
    static final String SYSTEM_PROMPT = "You are an operations assistant.";
    void run() { client.chat().completions().create(params.model("claude-sonnet-4-5")); }
}
