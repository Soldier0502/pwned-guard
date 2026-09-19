// Express: reusable middleware for any route that receives a new password.
import express, { type NextFunction, type Request, type Response } from "express";
import { createPwnedGuard } from "@soldier0502/pwned-guard";

const guard = createPwnedGuard({ minLength: 10, errorPolicy: "fail-open" });

export function rejectBreachedPassword(field = "password") {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const password = req.body?.[field];

    if (typeof password !== "string") {
      res.status(400).json({ error: `Missing field: ${field}` });
      return;
    }

    const result = await guard.check(password);

    if (!result.allowed) {
      res.status(422).json({ error: "password-rejected", reason: result.reason });
      return;
    }

    next();
  };
}

const app = express();
app.use(express.json());
app.post("/register", rejectBreachedPassword(), (_req, res) => res.status(201).json({ ok: true }));
app.post("/password/change", rejectBreachedPassword("newPassword"), (_req, res) => res.json({ ok: true }));

export default app;
