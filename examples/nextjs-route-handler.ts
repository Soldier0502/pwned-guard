// Next.js App Router: app/api/auth/register/route.ts
//
// One guard instance per server process, so the prefix cache is shared across
// requests. Creating it inside the handler would throw the cache away every
// time.
import { createPwnedGuard } from "@soldier0502/pwned-guard";

const guard = createPwnedGuard({
  maxBreaches: 0,
  minLength: 10,
  errorPolicy: "fail-open",
  // Terms that are obvious for your own product. Cheap, local, no network.
  localBlocklist: ["carissa", "carissa2026", "securedesk"],
});

const MESSAGES: Record<string, string> = {
  "too-short": "La contraseña es demasiado corta.",
  blocklisted: "Esa contraseña es demasiado predecible para esta aplicación.",
  breached: "Esa contraseña aparece en filtraciones públicas. Elige otra.",
};

export async function POST(request: Request): Promise<Response> {
  const { email, password } = (await request.json()) as { email: string; password: string };

  const result = await guard.check(password);

  if (!result.allowed) {
    // Do not tell the user how many times it appeared: combined with their
    // email that is a hint worth having for an attacker.
    return Response.json(
      { error: MESSAGES[result.reason] ?? "Contraseña no válida." },
      { status: 422 },
    );
  }

  if (result.source === "error") {
    // Availability kept, but leave a trace. Never log the password itself.
    console.warn("pwned-guard: breach lookup failed, password accepted", {
      email,
      error: result.error?.message,
    });
  }

  // ... create the user here ...
  return Response.json({ ok: true }, { status: 201 });
}
