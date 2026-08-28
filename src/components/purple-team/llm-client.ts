const LLM_TIMEOUT_MS     = 180_000;
const LLM_RETRY_DELAY_MS =  30_000;
const LLM_MAX_RETRIES    = 2;

export async function callLLM(apiKey: string, prompt: string): Promise<string> {
  let lastErr: Error = new Error('LLM call failed');

  for (let attempt = 0; attempt <= LLM_MAX_RETRIES; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, LLM_RETRY_DELAY_MS));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'nvidia/nemotron-3.5-lightning:free',
          messages: [{ role: 'user', content: prompt }],
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text();
        lastErr = new Error(`OpenRouter error ${response.status}: ${text}`);
        if (response.status === 429 || response.status >= 500) continue;
        throw lastErr;
      }

      const data = await response.json() as any;
      return data.choices[0].message.content as string;
    } catch (err: any) {
      if (err.name === 'AbortError') throw new Error(`LLM request timed out after ${LLM_TIMEOUT_MS / 1000}s`);
      lastErr = err;
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastErr;
}
