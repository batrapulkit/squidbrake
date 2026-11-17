type Decision = {
  event_id: string;
  decision: "allow" | "deny" | "review";
  reason: string;
  decision_note?: string | null;
};

type GuardOptions = {
  url: string;
  key: string;
  source?: string;
  sessionId?: string;
};

export function guard<TArgs extends unknown[], TResult>(
  name: string,
  options: GuardOptions,
  fn: (...args: TArgs) => TResult | Promise<TResult>,
): (...args: TArgs) => Promise<TResult> {
  const baseUrl = options.url.replace(/\/+$/, "");
  const headers = {
    "Content-Type": "application/json",
    "X-Gateway-Key": options.key,
  };

  async function json<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await fetch(url, { ...init, headers: { ...headers, ...init?.headers } });
    if (!response.ok) throw new Error(`Squidbrake returned HTTP ${response.status}`);
    return response.json() as Promise<T>;
  }

  return async (...args: TArgs): Promise<TResult> => {
    let decision = await json<Decision>(`${baseUrl}/v1/events`, {
      method: "POST",
      body: JSON.stringify({
        name,
        input: args,
        source: options.source ?? "typescript-example",
        session_id: options.sessionId,
      }),
    });

    while (decision.decision === "review") {
      decision = await json<Decision>(
        `${baseUrl}/v1/events/${encodeURIComponent(decision.event_id)}/decision?wait=25`,
      );
    }

    if (decision.decision === "deny") {
      throw new Error(`Squidbrake denied ${name}: ${decision.decision_note || decision.reason}`);
    }
    if (decision.decision !== "allow") {
      throw new Error(`Squidbrake returned an unknown decision for ${name}`);
    }

    const started = Date.now();
    let output: TResult;
    let actionError: unknown;
    let failed = false;
    try {
      output = await fn(...args);
    } catch (error) {
      failed = true;
      actionError = error;
    }

    await json(`${baseUrl}/v1/events/${encodeURIComponent(decision.event_id)}/result`, {
      method: "POST",
      body: JSON.stringify({
        output: failed ? undefined : output!,
        error: failed ? String(actionError) : null,
        duration_ms: Date.now() - started,
      }),
    });

    if (failed) throw actionError;
    return output!;
  };
}
