// Deliberately vulnerable static-analysis fixture; do not deploy or execute.
package main

import openai "github.com/sashabaranov/go-openai"

systemPrompt := "You are an operations assistant."

func handle(client *openai.Client, issue string) {
	client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: "gpt-4.1",
	})
}
