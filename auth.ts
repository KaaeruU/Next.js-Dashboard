import NextAuth from "next-auth";
import { authConfig } from "./auth-config";
import Credentials from "next-auth/providers/credentials";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";
import postgres from "postgres";
import { z } from "zod"; // Import mancante!

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) {
            // Restituisci solo i campi necessari per NextAuth
            return {
              id: user.id,
              email: user.email,
              name: user.name, // assumi che il tuo User type abbia un campo name
            };
          }
        }

        console.log("Invalid credentials");
        return null;
      },
    }),
  ],
});
